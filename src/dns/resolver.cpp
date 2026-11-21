#include "dns/resolver.h"

#include "dns/servers.h"
#include "net/addr.h"

#include <algorithm>
#include <cstring>
#include <utility>

namespace wc::dns {
namespace {

constexpr uint32_t kMaxInflightCap = 32768;  // slot index + 1 must fit by_txid_'s uint16_t
constexpr size_t kRecvDepth = 64;
constexpr int kRecvBufferBytes = 4 << 20;

// Strict dotted quad: four decimal parts 0..255, no leading '+', no port.
bool parse_ipv4_literal(std::string_view s, uint32_t& out_be) {
    uint8_t bytes[4];
    size_t pos = 0;
    for (int part = 0; part < 4; ++part) {
        if (part != 0) {
            if (pos >= s.size() || s[pos] != '.') return false;
            ++pos;
        }
        unsigned value = 0;
        size_t digits = 0;
        while (pos < s.size() && s[pos] >= '0' && s[pos] <= '9' && digits < 3) {
            value = value * 10 + static_cast<unsigned>(s[pos] - '0');
            ++pos;
            ++digits;
        }
        if (digits == 0 || value > 255) return false;
        bytes[part] = static_cast<uint8_t>(value);
    }
    if (pos != s.size()) return false;
    std::memcpy(&out_be, bytes, 4);
    return true;
}

bool same_endpoint(const sockaddr_in& a, const sockaddr_in& b) {
    return a.sin_addr.s_addr == b.sin_addr.s_addr && a.sin_port == b.sin_port;
}

std::mt19937 seeded_rng() {
    std::random_device rd;
    std::seed_seq seq{rd(), rd(), rd(), rd()};
    return std::mt19937(seq);
}

}  // namespace

const char* status_name(Status status) {
    switch (status) {
    case Status::Ok: return "ok";
    case Status::NxDomain: return "nxdomain";
    case Status::NoAnswer: return "noanswer";
    case Status::ServFail: return "servfail";
    case Status::Timeout: return "timeout";
    case Status::Invalid: return "invalid";
    }
    return "?";
}

Resolver::Resolver(net::Loop& loop, ResolverConfig config)
    : loop_(loop), config_(std::move(config)), socket_(loop, *this), by_txid_(65536, 0), rng_(seeded_rng()) {
    if (config_.servers.empty()) config_.servers = system_dns_servers();
    config_.attempts = std::max<uint32_t>(config_.attempts, 1);
    config_.max_inflight = std::clamp<uint32_t>(config_.max_inflight, 1, kMaxInflightCap);

    slots_.resize(config_.max_inflight);
    free_slots_.reserve(config_.max_inflight);
    // Reverse so slot 0 is handed out first; keeps the hot slots dense.
    for (uint32_t i = config_.max_inflight; i-- > 0;) free_slots_.push_back(i);

    // Port 0: the OS picks a fresh ephemeral source port per resolver.
    open_error_ = socket_.open(net::make_addr(INADDR_ANY, 0), kRecvDepth, kRecvBufferBytes);
}

Resolver::~Resolver() = default;

void Resolver::post_result(Callback&& cb, Status status, uint32_t ipv4_be) {
    // Captures only the callback so a queued result never touches the resolver.
    loop_.post([cb = std::move(cb), status, ipv4_be] { cb(status, ipv4_be); });
}

void Resolver::resolve(std::string_view host, Callback cb) {
    if (shut_down_) {
        ++counters_.cancelled;
        post_result(std::move(cb), Status::Timeout, 0);
        return;
    }
    uint32_t literal = 0;
    if (parse_ipv4_literal(host, literal)) {
        ++counters_.literals;
        post_result(std::move(cb), Status::Ok, literal);
        return;
    }
    uint8_t probe[kMaxQuerySize];
    if (build_query(0, host, kTypeA, probe, sizeof probe) == 0) {
        ++counters_.invalid;
        post_result(std::move(cb), Status::Invalid, 0);
        return;
    }
    if (open_error_ != 0 || config_.servers.empty()) {
        ++counters_.servfail;
        post_result(std::move(cb), Status::ServFail, 0);
        return;
    }

    std::string name(host);
    if (name.back() == '.') name.pop_back();
    for (char& c : name) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + ('a' - 'A'));
    }
    if (free_slots_.empty() || !queue_.empty()) {
        queue_.push_back({std::move(name), std::move(cb)});
        return;
    }
    start(std::move(name), std::move(cb));
}

void Resolver::start(std::string&& host, Callback&& cb) {
    const uint32_t index = free_slots_.back();
    free_slots_.pop_back();
    Slot& slot = slots_[index];

    uint16_t txid;
    do {
        txid = static_cast<uint16_t>(rng_());
    } while (by_txid_[txid] != 0);
    by_txid_[txid] = static_cast<uint16_t>(index + 1);

    slot.host = std::move(host);
    slot.cb = std::move(cb);
    slot.txid = txid;
    slot.attempt = 0;
    // Spread first attempts across servers; retries rotate from there.
    slot.server = next_server_;
    next_server_ = (next_server_ + 1) % static_cast<uint32_t>(config_.servers.size());
    slot.active = true;
    send_attempt(index);
}

void Resolver::send_attempt(uint32_t index) {
    Slot& slot = slots_[index];
    uint8_t packet[kMaxQuerySize];
    const size_t len = build_query(slot.txid, slot.host, kTypeA, packet, sizeof packet);
    // A failed send is left to the attempt timer, which retries on the next server.
    if (socket_.send_to(config_.servers[slot.server], reinterpret_cast<const char*>(packet), len)) {
        ++counters_.queries_sent;
    } else {
        ++counters_.send_errors;
    }
    const uint16_t txid = slot.txid;
    slot.timer = loop_.add_timer(config_.timeout_ms, [this, index, txid] { on_timeout(index, txid); });
}

void Resolver::on_timeout(uint32_t index, uint16_t txid) {
    Slot& slot = slots_[index];
    if (!slot.active || slot.txid != txid) return;
    slot.timer = 0;
    ++counters_.attempt_timeouts;
    retry_or_fail(index, Status::Timeout);
}

void Resolver::retry_or_fail(uint32_t index, Status final_status) {
    Slot& slot = slots_[index];
    if (slot.attempt + 1 >= config_.attempts) {
        finish(index, final_status, 0);
        return;
    }
    if (slot.timer != 0) {
        loop_.cancel_timer(slot.timer);
        slot.timer = 0;
    }
    ++slot.attempt;
    ++counters_.retries;
    slot.server = (slot.server + 1) % static_cast<uint32_t>(config_.servers.size());
    send_attempt(index);
}

void Resolver::finish(uint32_t index, Status status, uint32_t ipv4_be) {
    Slot& slot = slots_[index];
    if (slot.timer != 0) {
        loop_.cancel_timer(slot.timer);
        slot.timer = 0;
    }
    by_txid_[slot.txid] = 0;
    slot.active = false;
    Callback cb = std::move(slot.cb);
    slot.cb = nullptr;
    free_slots_.push_back(index);

    switch (status) {
    case Status::Ok: ++counters_.ok; break;
    case Status::NxDomain: ++counters_.nxdomain; break;
    case Status::NoAnswer: ++counters_.noanswer; break;
    case Status::ServFail: ++counters_.servfail; break;
    case Status::Timeout: ++counters_.timeouts; break;
    case Status::Invalid: ++counters_.invalid; break;
    }

    // Refill before the callback so a re-entrant resolve() queues behind
    // older requests instead of jumping the FIFO.
    if (!queue_.empty()) {
        Pending next = std::move(queue_.front());
        queue_.pop_front();
        start(std::move(next.host), std::move(next.cb));
    }
    cb(status, ipv4_be);
}

void Resolver::on_datagram(net::UdpSocket&, const char* data, size_t len, const sockaddr_in& from) {
    if (shut_down_) return;
    const bool known_server = std::any_of(config_.servers.begin(), config_.servers.end(),
                                          [&](const sockaddr_in& s) { return same_endpoint(s, from); });
    if (!known_server) {
        ++counters_.mismatched;
        return;
    }
    Response& r = response_;
    if (!parse_response(reinterpret_cast<const uint8_t*>(data), len, r)) {
        ++counters_.malformed;
        return;
    }
    const uint16_t slot_ref = by_txid_[r.id];
    if (slot_ref == 0 || !r.qr || r.qtype != kTypeA || r.qclass != kClassIn) {
        ++counters_.mismatched;
        return;
    }
    const uint32_t index = slot_ref - 1u;
    if (!name_equal(r.question(), slots_[index].host)) {
        ++counters_.mismatched;
        return;
    }

    switch (r.rcode) {
    case kNoError:
        if (!r.tc && r.addr_count != 0) {
            finish(index, Status::Ok, r.addrs[0]);
        } else {
            finish(index, Status::NoAnswer, 0);
        }
        break;
    case kNxDomain:
        finish(index, Status::NxDomain, 0);
        break;
    default:  // SERVFAIL, REFUSED, FORMERR, NOTIMP...: another server may do better
        retry_or_fail(index, Status::ServFail);
        break;
    }
}

void Resolver::shutdown() {
    if (shut_down_) return;
    shut_down_ = true;

    std::vector<Callback> failed;
    failed.reserve(inflight() + queue_.size());
    for (Slot& slot : slots_) {
        if (!slot.active) continue;
        if (slot.timer != 0) loop_.cancel_timer(slot.timer);
        slot.timer = 0;
        by_txid_[slot.txid] = 0;
        slot.active = false;
        failed.push_back(std::move(slot.cb));
        slot.cb = nullptr;
    }
    free_slots_.clear();
    for (uint32_t i = static_cast<uint32_t>(slots_.size()); i-- > 0;) free_slots_.push_back(i);
    for (Pending& p : queue_) failed.push_back(std::move(p.cb));
    queue_.clear();
    counters_.cancelled += failed.size();

    socket_.close();
    if (!failed.empty()) {
        loop_.post([failed = std::move(failed)] {
            for (const Callback& cb : failed) cb(Status::Timeout, 0);
        });
    }
}

}  // namespace wc::dns

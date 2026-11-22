#include "dns/resolver.h"

#include "dns/servers.h"
#include "net/addr.h"

#include <algorithm>
#include <cstring>
#include <utility>

namespace wc::dns {
namespace {

// A reply up to the advertised size must fit one receive buffer, or the
// socket would drop exactly the large answers EDNS asked for.
static_assert(kEdnsUdpSize <= net::UdpSocket::kRecvBufferSize);

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
    // RFC 6891 treats sizes below 512 as 512; above the receive buffer, the
    // socket would drop the very replies the size invites.
    if (config_.edns_udp_size != 0) {
        config_.edns_udp_size = std::clamp<uint16_t>(config_.edns_udp_size, 512,
                                                     static_cast<uint16_t>(net::UdpSocket::kRecvBufferSize));
    }

    slots_.resize(config_.max_inflight);
    free_slots_.reserve(config_.max_inflight);
    // Reverse so slot 0 is handed out first; keeps the hot slots dense.
    for (uint32_t i = config_.max_inflight; i-- > 0;) free_slots_.push_back(i);

    // Port 0: the OS picks a fresh ephemeral source port per resolver.
    open_error_ = socket_.open(net::make_addr(INADDR_ANY, 0), kRecvDepth, kRecvBufferBytes);
}

Resolver::~Resolver() = default;

void Resolver::post_result(Callback&& cb, HttpsCallback&& https_cb, Status status, uint32_t ipv4_be) {
    // Captures only the callback so a queued result never touches the resolver.
    if (cb) {
        loop_.post([cb = std::move(cb), status, ipv4_be] { cb(status, ipv4_be); });
    } else {
        loop_.post([cb = std::move(https_cb), status] { cb(status, HttpsRecord{}); });
    }
}

void Resolver::resolve(std::string_view host, Callback cb) {
    uint32_t literal = 0;
    if (!shut_down_ && parse_ipv4_literal(host, literal)) {
        ++counters_.literals;
        post_result(std::move(cb), nullptr, Status::Ok, literal);
        return;
    }
    submit(host, kTypeA, std::move(cb), nullptr);
}

void Resolver::resolve_https(std::string_view host, HttpsCallback cb) {
    ++counters_.https_requests;
    uint32_t literal = 0;
    if (!shut_down_ && parse_ipv4_literal(host, literal)) {
        ++counters_.literals;
        post_result(nullptr, std::move(cb), Status::NoAnswer, 0);
        return;
    }
    submit(host, kTypeHttps, nullptr, std::move(cb));
}

void Resolver::submit(std::string_view host, uint16_t qtype, Callback&& cb, HttpsCallback&& https_cb) {
    if (shut_down_) {
        ++counters_.cancelled;
        post_result(std::move(cb), std::move(https_cb), Status::Timeout, 0);
        return;
    }
    uint8_t probe[kMaxQuerySize];
    if (build_query(0, host, qtype, probe, sizeof probe) == 0) {
        ++counters_.invalid;
        post_result(std::move(cb), std::move(https_cb), Status::Invalid, 0);
        return;
    }
    if (open_error_ != 0 || config_.servers.empty()) {
        ++counters_.servfail;
        post_result(std::move(cb), std::move(https_cb), Status::ServFail, 0);
        return;
    }

    Pending request{std::string(host), qtype, std::move(cb), std::move(https_cb)};
    std::string& name = request.host;
    if (name.back() == '.') name.pop_back();
    for (char& c : name) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + ('a' - 'A'));
    }
    if (free_slots_.empty() || !queue_.empty()) {
        queue_.push_back(std::move(request));
        return;
    }
    start(std::move(request));
}

void Resolver::start(Pending&& request) {
    const uint32_t index = free_slots_.back();
    free_slots_.pop_back();
    Slot& slot = slots_[index];

    uint16_t txid;
    do {
        txid = static_cast<uint16_t>(rng_());
    } while (by_txid_[txid] != 0);
    by_txid_[txid] = static_cast<uint16_t>(index + 1);

    slot.host = std::move(request.host);
    slot.cb = std::move(request.cb);
    slot.https_cb = std::move(request.https_cb);
    slot.qtype = request.qtype;
    slot.txid = txid;
    slot.attempt = 0;
    slot.edns = config_.edns_udp_size != 0;
    // Spread first attempts across servers; retries rotate from there.
    slot.server = next_server_;
    next_server_ = (next_server_ + 1) % static_cast<uint32_t>(config_.servers.size());
    slot.active = true;
    send_attempt(index);
}

void Resolver::send_attempt(uint32_t index) {
    Slot& slot = slots_[index];
    uint8_t packet[kMaxQuerySize];
    const size_t len =
        build_query(slot.txid, slot.host, slot.qtype, packet, sizeof packet, slot.edns ? config_.edns_udp_size : 0);
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
        finish(index, final_status, nullptr);
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

void Resolver::finish(uint32_t index, Status status, const Response* reply) {
    Slot& slot = slots_[index];
    if (slot.timer != 0) {
        loop_.cancel_timer(slot.timer);
        slot.timer = 0;
    }
    by_txid_[slot.txid] = 0;
    slot.active = false;
    Callback cb = std::move(slot.cb);
    HttpsCallback https_cb = std::move(slot.https_cb);
    slot.cb = nullptr;
    slot.https_cb = nullptr;
    free_slots_.push_back(index);

    switch (status) {
    case Status::Ok: ++counters_.ok; break;
    case Status::NxDomain: ++counters_.nxdomain; break;
    case Status::NoAnswer: ++counters_.noanswer; break;
    case Status::ServFail: ++counters_.servfail; break;
    case Status::Timeout: ++counters_.timeouts; break;
    case Status::Invalid: ++counters_.invalid; break;
    }

    uint32_t ipv4_be = 0;
    HttpsRecord record;
    if (cb) {
        if (status == Status::Ok) ipv4_be = reply->addrs[0];
    } else if (reply != nullptr) {
        record.malformed = reply->https_malformed;
        record.cname_hops = reply->cname_hops;
        if (record.malformed) ++counters_.https_malformed;
        if (status == Status::Ok) {
            const HttpsRr& rr = reply->https;
            ++counters_.https_present;
            record.present = true;
            record.alias_mode = rr.alias_mode();
            record.priority = rr.priority;
            record.target.assign(rr.target_name());
            record.alpn_h3 = rr.alpn_h3;
            record.alpn_h2 = rr.alpn_h2;
            record.alpn_http11 = rr.alpn_http11;
            record.ech = rr.ech;
            record.port = rr.port;
            record.no_default_alpn = rr.no_default_alpn;
            record.ipv4hint = rr.ipv4hint;
            record.ipv6hint = rr.ipv6hint;
            record.rrset_size = reply->https_count;
        }
    }

    // Refill before the callback so a re-entrant resolve() queues behind
    // older requests instead of jumping the FIFO.
    if (!queue_.empty()) {
        Pending next = std::move(queue_.front());
        queue_.pop_front();
        start(std::move(next));
    }
    if (cb) {
        cb(status, ipv4_be);
    } else {
        https_cb(status, record);
    }
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
    if (!r.qr || (r.qtype != kTypeA && r.qtype != kTypeHttps) || r.qclass != kClassIn) {
        ++counters_.mismatched;
        return;
    }
    if (slot_ref == 0) {
        ++counters_.late;  // usually the first server answering after a retry already completed the query
        return;
    }
    const uint32_t index = slot_ref - 1u;
    Slot& slot = slots_[index];
    if (r.qtype != slot.qtype || !name_equal(r.question(), slot.host)) {
        ++counters_.mismatched;
        return;
    }

    switch (r.rcode) {
    case kNoError:
        if (r.tc) {
            ++counters_.truncated;
            finish(index, Status::NoAnswer, nullptr);
        } else if (slot.qtype == kTypeA) {
            finish(index, r.addr_count != 0 ? Status::Ok : Status::NoAnswer, &r);
        } else {
            finish(index, r.https_count != 0 && !r.https_malformed ? Status::Ok : Status::NoAnswer, &r);
        }
        break;
    case kNxDomain:
        finish(index, Status::NxDomain, nullptr);
        break;
    case kFormErr:
        // Possibly a server that rejects EDNS; later attempts go without it.
        if (slot.edns) {
            slot.edns = false;
            ++counters_.edns_fallbacks;
        }
        retry_or_fail(index, Status::ServFail);
        break;
    default:  // SERVFAIL, REFUSED, NOTIMP...: another server may do better
        retry_or_fail(index, Status::ServFail);
        break;
    }
}

void Resolver::shutdown() {
    if (shut_down_) return;
    shut_down_ = true;

    std::vector<Callback> failed;
    std::vector<HttpsCallback> failed_https;
    for (Slot& slot : slots_) {
        if (!slot.active) continue;
        if (slot.timer != 0) loop_.cancel_timer(slot.timer);
        slot.timer = 0;
        by_txid_[slot.txid] = 0;
        slot.active = false;
        if (slot.cb) {
            failed.push_back(std::move(slot.cb));
        } else {
            failed_https.push_back(std::move(slot.https_cb));
        }
        slot.cb = nullptr;
        slot.https_cb = nullptr;
    }
    free_slots_.clear();
    for (uint32_t i = static_cast<uint32_t>(slots_.size()); i-- > 0;) free_slots_.push_back(i);
    for (Pending& p : queue_) {
        if (p.cb) {
            failed.push_back(std::move(p.cb));
        } else {
            failed_https.push_back(std::move(p.https_cb));
        }
    }
    queue_.clear();
    counters_.cancelled += failed.size() + failed_https.size();

    socket_.close();
    if (!failed.empty() || !failed_https.empty()) {
        loop_.post([failed = std::move(failed), failed_https = std::move(failed_https)] {
            for (const Callback& cb : failed) cb(Status::Timeout, 0);
            const HttpsRecord none;
            for (const HttpsCallback& cb : failed_https) cb(Status::Timeout, none);
        });
    }
}

}  // namespace wc::dns

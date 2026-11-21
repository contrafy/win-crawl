#include "benchsrv/dns_server.h"

#include <cstring>

namespace wc::benchsrv {

namespace {

constexpr uint16_t kFlagQr = 0x8000;
constexpr uint16_t kFlagAa = 0x0400;
constexpr uint16_t kFlagRd = 0x0100;
constexpr uint16_t kFlagRa = 0x0080;
constexpr uint16_t kRcodeFormErr = 1;
constexpr uint16_t kRcodeNxDomain = 3;
constexpr uint16_t kRcodeNotImp = 4;
constexpr uint16_t kRcodeRefused = 5;
constexpr uint16_t kTypeA = 1;
constexpr uint16_t kTypeAny = 255;
constexpr uint16_t kClassIn = 1;
constexpr uint32_t kTtl = 300;

uint16_t get16(const char* p) {
    return static_cast<uint16_t>((static_cast<unsigned char>(p[0]) << 8) | static_cast<unsigned char>(p[1]));
}

void put16(std::vector<char>& out, uint16_t v) {
    out.push_back(static_cast<char>(v >> 8));
    out.push_back(static_cast<char>(v & 0xFF));
}

void set16(std::vector<char>& out, size_t at, uint16_t v) {
    out[at] = static_cast<char>(v >> 8);
    out[at + 1] = static_cast<char>(v & 0xFF);
}

// Header with QDCOUNT = qd and zero other counts; flags filled in by the caller.
void put_header(std::vector<char>& out, uint16_t id, uint16_t flags, uint16_t qd) {
    put16(out, id);
    put16(out, flags);
    put16(out, qd);
    put16(out, 0);
    put16(out, 0);
    put16(out, 0);
}

bool in_zone(std::string_view name, std::string_view zone) {
    if (name == zone) return true;
    return name.size() > zone.size() && name[name.size() - zone.size() - 1] == '.' &&
           name.substr(name.size() - zone.size()) == zone;
}

}  // namespace

DnsOutcome build_dns_reply(const Behavior& behavior, const char* query, size_t len, std::vector<char>& out,
                           uint64_t& delay_key) {
    out.clear();
    delay_key = 0;
    if (len < 12) return DnsOutcome::Drop;
    const uint16_t id = get16(query);
    const uint16_t qflags = get16(query + 2);
    if (qflags & kFlagQr) return DnsOutcome::Drop;
    const uint16_t opcode = (qflags >> 11) & 0xF;
    const uint16_t base_flags = static_cast<uint16_t>(kFlagQr | (opcode << 11) | (qflags & kFlagRd) | kFlagRa);

    if (opcode != 0) {
        put_header(out, id, base_flags | kRcodeNotImp, 0);
        return DnsOutcome::Error;
    }
    if (get16(query + 4) != 1) {
        put_header(out, id, base_flags | kRcodeFormErr, 0);
        return DnsOutcome::Error;
    }

    // QNAME: uncompressed labels, lowercased into `name`.
    char name[256];
    size_t name_len = 0;
    size_t pos = 12;
    for (;;) {
        if (pos >= len) {
            put_header(out, id, base_flags | kRcodeFormErr, 0);
            return DnsOutcome::Error;
        }
        const auto label = static_cast<unsigned char>(query[pos++]);
        if (label == 0) break;
        if (label > 63 || pos + label > len || name_len + label + 1 > 253) {
            put_header(out, id, base_flags | kRcodeFormErr, 0);
            return DnsOutcome::Error;
        }
        if (name_len > 0) name[name_len++] = '.';
        for (size_t i = 0; i < label; ++i) {
            char c = query[pos + i];
            name[name_len++] = (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
        }
        pos += label;
    }
    if (pos + 4 > len) {
        put_header(out, id, base_flags | kRcodeFormErr, 0);
        return DnsOutcome::Error;
    }
    const uint16_t qtype = get16(query + pos);
    const uint16_t qclass = get16(query + pos + 2);
    pos += 4;
    const std::string_view qname(name, name_len);

    // Echo the question section verbatim (preserves the client's 0x20 casing).
    put_header(out, id, base_flags, 1);
    out.insert(out.end(), query + 12, query + pos);

    const auto n = parse_host_name(qname, behavior.zone);
    delay_key = n ? *n : fnv1a(qname);

    if (!in_zone(qname, behavior.zone) || qclass != kClassIn) {
        set16(out, 2, base_flags | kRcodeRefused);
        return DnsOutcome::Refused;
    }
    if (!n || host_nxdomain(behavior, *n)) {
        set16(out, 2, base_flags | kFlagAa | kRcodeNxDomain);
        return DnsOutcome::NxDomain;
    }
    set16(out, 2, base_flags | kFlagAa);
    if (qtype != kTypeA && qtype != kTypeAny) return DnsOutcome::NoData;

    set16(out, 6, 1);  // ANCOUNT
    put16(out, 0xC00C);  // pointer to the question name
    put16(out, kTypeA);
    put16(out, kClassIn);
    put16(out, static_cast<uint16_t>(kTtl >> 16));
    put16(out, static_cast<uint16_t>(kTtl & 0xFFFF));
    put16(out, 4);
    const uint32_t ip = host_ip(behavior, *n);
    const char* ip_bytes = reinterpret_cast<const char*>(&ip);  // already network order
    out.insert(out.end(), ip_bytes, ip_bytes + 4);
    return DnsOutcome::Answered;
}

DnsServer::DnsServer(const Behavior& behavior) : behavior_(behavior) { reply_.reserve(512); }

DnsServer::~DnsServer() { stop(); }

DWORD DnsServer::start(const sockaddr_in& local) {
    socket_.emplace(loop_, static_cast<net::UdpHandler&>(*this));
    // Deep receive queue: the crawler bursts thousands of queries at once.
    const DWORD err = socket_->open(local, 64, 8 << 20);
    if (err != 0) {
        socket_.reset();
        return err;
    }
    local_ = socket_->local_address();
    thread_ = std::thread([this] { loop_.run(); });
    return 0;
}

void DnsServer::stop() {
    if (!thread_.joinable()) return;
    loop_.post([this] { shutdown_on_loop(); });
    thread_.join();
    socket_.reset();
}

DnsCounters DnsServer::counters() const {
    DnsCounters c;
    c.queries = stats_.queries.load(std::memory_order_relaxed);
    c.answered = stats_.answered.load(std::memory_order_relaxed);
    c.nodata = stats_.nodata.load(std::memory_order_relaxed);
    c.nxdomain = stats_.nxdomain.load(std::memory_order_relaxed);
    c.refused = stats_.refused.load(std::memory_order_relaxed);
    c.errors = stats_.errors.load(std::memory_order_relaxed);
    return c;
}

namespace {
// Single-writer counter bump without a locked RMW.
void bump(std::atomic<uint64_t>& counter) {
    counter.store(counter.load(std::memory_order_relaxed) + 1, std::memory_order_relaxed);
}
}  // namespace

void DnsServer::on_datagram(net::UdpSocket& socket, const char* data, size_t len, const sockaddr_in& from) {
    if (stopping_) return;
    uint64_t delay_key = 0;
    const DnsOutcome outcome = build_dns_reply(behavior_, data, len, reply_, delay_key);
    if (outcome == DnsOutcome::Drop) return;
    bump(stats_.queries);
    switch (outcome) {
        case DnsOutcome::Answered: bump(stats_.answered); break;
        case DnsOutcome::NoData: bump(stats_.nodata); break;
        case DnsOutcome::NxDomain: bump(stats_.nxdomain); break;
        case DnsOutcome::Refused: bump(stats_.refused); break;
        default: bump(stats_.errors); break;
    }

    const uint32_t delay = dns_delay_ms(behavior_, delay_key);
    if (delay == 0 || reply_.size() > sizeof(Pending::data)) {
        socket.send_to(from, reply_.data(), reply_.size());
        return;
    }
    // Delayed reply: park a copy in a pooled slot so the timer callback stays
    // small enough for std::function's inline storage.
    uint32_t index = free_head_;
    if (index == UINT32_MAX) {
        index = static_cast<uint32_t>(pending_.size());
        pending_.push_back(std::make_unique<Pending>());
        pending_timers_.push_back(0);
    } else {
        free_head_ = pending_[index]->next_free;
    }
    Pending& p = *pending_[index];
    p.to = from;
    p.len = static_cast<uint16_t>(reply_.size());
    std::memcpy(p.data, reply_.data(), reply_.size());
    pending_timers_[index] = loop_.add_timer(delay, [this, index] { send_pending(index); });
}

void DnsServer::send_pending(uint32_t index) {
    Pending& p = *pending_[index];
    pending_timers_[index] = 0;
    if (!stopping_) socket_->send_to(p.to, p.data, p.len);
    p.next_free = free_head_;
    free_head_ = index;
}

void DnsServer::shutdown_on_loop() {
    stopping_ = true;
    for (net::TimerId& id : pending_timers_) {
        if (id != 0) loop_.cancel_timer(id);
        id = 0;
    }
    socket_->close();
    // Aborted receives complete on later iterations; stop once they have.
    struct Drain {
        static void check(DnsServer* self) {
            if (self->socket_->busy()) {
                self->loop_.add_timer(1, [self] { check(self); });
            } else {
                self->loop_.stop();
            }
        }
    };
    Drain::check(this);
}

}  // namespace wc::benchsrv

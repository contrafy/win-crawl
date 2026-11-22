#include "dns/resolver.h"

#include "doctest/doctest.h"
#include "net/addr.h"

#include <cstring>
#include <functional>
#include <initializer_list>
#include <set>
#include <string>
#include <vector>

using namespace wc;
using dns::Status;

namespace {

uint32_t ip(uint8_t x, uint8_t y, uint8_t z, uint8_t w) {
    const uint8_t bytes[4] = {x, y, z, w};
    uint32_t v;
    std::memcpy(&v, bytes, 4);
    return v;
}

void put_u16(std::vector<uint8_t>& b, uint16_t v) {
    b.push_back(static_cast<uint8_t>(v >> 8));
    b.push_back(static_cast<uint8_t>(v));
}

// Offset just past the (uncompressed) question of a query we built.
size_t question_end(const std::vector<uint8_t>& q) {
    size_t p = dns::kHeaderSize;
    while (q[p] != 0) p += 1 + static_cast<size_t>(q[p]);
    return p + 5;
}

uint16_t query_type(const std::vector<uint8_t>& q) {
    const size_t end = question_end(q);
    return static_cast<uint16_t>((q[end - 4] << 8) | q[end - 3]);
}

// True when the query ends with exactly the OPT record build_query writes.
bool has_edns(const std::vector<uint8_t>& q) {
    const size_t end = question_end(q);
    const uint8_t opt[11] = {0, 0, dns::kTypeOpt, dns::kEdnsUdpSize >> 8, dns::kEdnsUdpSize & 0xFF, 0, 0, 0, 0, 0, 0};
    return q[10] == 0 && q[11] == 1 && q.size() == end + sizeof opt && std::memcmp(q.data() + end, opt, sizeof opt) == 0;
}

// Reply echoing `query`'s header and question (additional section dropped)
// with the given rcode/answers.
std::vector<uint8_t> make_reply(const std::vector<uint8_t>& query, uint8_t rcode, std::initializer_list<uint32_t> addrs,
                                bool tc = false) {
    std::vector<uint8_t> b(query.begin(), query.begin() + static_cast<ptrdiff_t>(question_end(query)));
    const uint16_t flags = static_cast<uint16_t>(0x8180 | rcode | (tc ? 0x0200 : 0));
    b[2] = static_cast<uint8_t>(flags >> 8);
    b[3] = static_cast<uint8_t>(flags);
    b[6] = 0;
    b[7] = static_cast<uint8_t>(addrs.size());
    b[10] = 0;
    b[11] = 0;
    for (uint32_t a : addrs) {
        put_u16(b, 0xC00C);
        put_u16(b, dns::kTypeA);
        put_u16(b, dns::kClassIn);
        put_u16(b, 0);
        put_u16(b, 60);
        put_u16(b, 4);
        const auto* p = reinterpret_cast<const uint8_t*>(&a);
        b.insert(b.end(), p, p + 4);
    }
    return b;
}

// Appends one answer record owned by the name at `owner` (a compression offset).
void add_rr(std::vector<uint8_t>& b, uint16_t owner, uint16_t type, const std::vector<uint8_t>& rdata) {
    put_u16(b, static_cast<uint16_t>(0xC000 | owner));
    put_u16(b, type);
    put_u16(b, dns::kClassIn);
    put_u16(b, 0);
    put_u16(b, 60);
    put_u16(b, static_cast<uint16_t>(rdata.size()));
    b.insert(b.end(), rdata.begin(), rdata.end());
    b[7] = static_cast<uint8_t>(b[7] + 1);
}

// 1 . alpn=h3,h2 ipv4hint=104.16.132.20 ech=<6 opaque bytes>
const std::vector<uint8_t> kSvcRdata = {0, 1, 0,                                          // priority, root target
                                        0, 1, 0, 6, 2, 'h', '3', 2, 'h', '2',             // alpn
                                        0, 4, 0, 4, 104, 16, 132, 20,                     // ipv4hint
                                        0, 5, 0, 8, 0, 6, 0xfe, 0x0d, 0, 2, 0xaa, 0xbb};  // ech
// 0 cdn.example.net
const std::vector<uint8_t> kAliasRdata = {0, 0, 3, 'c', 'd', 'n', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'n', 'e', 't', 0};
// 1 . port=443 alpn=h2: keys out of order
const std::vector<uint8_t> kBadRdata = {0, 1, 0, 0, 3, 0, 2, 1, 0xbb, 0, 1, 0, 3, 2, 'h', '2'};

// Same packet with the question type replaced.
std::vector<uint8_t> with_qtype(std::vector<uint8_t> b, uint16_t type) {
    const size_t end = question_end(b);
    b[end - 4] = static_cast<uint8_t>(type >> 8);
    b[end - 3] = static_cast<uint8_t>(type);
    return b;
}

class FakeDns;
using Behavior = std::function<void(FakeDns& server, const std::string& name, int nth,
                                    const std::vector<uint8_t>& query, const sockaddr_in& from)>;

// In-process DNS server on 127.0.0.1; `alt_` sends from a second port to
// impersonate an unexpected source.
class FakeDns final : public net::UdpHandler {
public:
    FakeDns(net::Loop& loop, Behavior behavior) : main_(loop, *this), alt_(loop, *this), behavior_(std::move(behavior)) {
        const sockaddr_in local = net::make_addr(htonl(INADDR_LOOPBACK), 0);
        REQUIRE(main_.open(local, 64, 1 << 20) == 0);
        REQUIRE(alt_.open(local, 1, 1 << 16) == 0);
    }

    sockaddr_in addr() const { return main_.local_address(); }
    void send(const std::vector<uint8_t>& packet, const sockaddr_in& to) {
        main_.send_to(to, reinterpret_cast<const char*>(packet.data()), packet.size());
    }
    void send_from_alt(const std::vector<uint8_t>& packet, const sockaddr_in& to) {
        alt_.send_to(to, reinterpret_cast<const char*>(packet.data()), packet.size());
    }
    void close() {
        main_.close();
        alt_.close();
    }
    bool busy() const { return main_.busy() || alt_.busy(); }

    struct Seen {
        std::string name;
        uint16_t id;
        uint16_t qtype;
        bool edns;
    };
    std::vector<Seen> seen;

private:
    void on_datagram(net::UdpSocket& socket, const char* data, size_t len, const sockaddr_in& from) override {
        if (&socket != &main_) return;
        dns::Response q;
        if (!dns::parse_response(reinterpret_cast<const uint8_t*>(data), len, q)) return;
        const std::string name(q.question());
        const std::vector<uint8_t> query(data, data + len);
        seen.push_back({name, q.id, q.qtype, has_edns(query)});
        int nth = 0;
        for (const Seen& s : seen) nth += s.name == name;
        behavior_(*this, name, nth, query, from);
    }

    net::UdpSocket main_;
    net::UdpSocket alt_;
    Behavior behavior_;
};

// HTTPS queries: answers by name; anything unknown is silently dropped.
void https_behavior(FakeDns& s, const std::string& name, int nth, const std::vector<uint8_t>& q,
                    const sockaddr_in& from) {
    std::vector<uint8_t> b = make_reply(q, dns::kNoError, {});
    if (name == "svc.test") {
        add_rr(b, 12, dns::kTypeHttps, kSvcRdata);
    } else if (name == "alias.test") {
        add_rr(b, 12, dns::kTypeHttps, kAliasRdata);
    } else if (name == "bad.test") {
        add_rr(b, 12, dns::kTypeHttps, kSvcRdata);
        add_rr(b, 12, dns::kTypeHttps, kBadRdata);
    } else if (name == "cname.test") {
        // cname.test CNAME svc.test, svc.test HTTPS <svc>
        const uint16_t target = static_cast<uint16_t>(b.size() + 12);
        add_rr(b, 12, dns::kTypeCname, {3, 's', 'v', 'c', 4, 't', 'e', 's', 't', 0});
        add_rr(b, target, dns::kTypeHttps, kSvcRdata);
    } else if (name == "nx.test") {
        b = make_reply(q, dns::kNxDomain, {});
    } else if (name == "tc.test") {
        b = make_reply(q, dns::kNoError, {}, true);
    } else if (name == "wrongtype.test") {
        // An A-typed reply with the right txid and name, then the real answer.
        s.send(make_reply(with_qtype(q, dns::kTypeA), dns::kNoError, {ip(6, 6, 6, 6)}), from);
        add_rr(b, 12, dns::kTypeHttps, kAliasRdata);
    } else if (name == "formerr.test") {
        if (has_edns(q)) {
            b = make_reply(q, dns::kFormErr, {});
        } else {
            add_rr(b, 12, dns::kTypeHttps, kSvcRdata);
        }
    } else if (name == "drop.test") {
        if (nth == 1) return;
    } else if (name != "a.test" && name != "empty.test") {
        return;  // a.test and empty.test: NODATA
    }
    s.send(b, from);
}

// Answers by name; anything unknown is silently dropped.
void standard_behavior(FakeDns& s, const std::string& name, int nth, const std::vector<uint8_t>& q,
                       const sockaddr_in& from) {
    if (query_type(q) == dns::kTypeHttps) {
        https_behavior(s, name, nth, q, from);
        return;
    }
    if (name == "a.test") {
        s.send(make_reply(q, dns::kNoError, {ip(10, 0, 0, 1), ip(10, 0, 0, 2)}), from);
    } else if (name == "nx.test") {
        s.send(make_reply(q, dns::kNxDomain, {}), from);
    } else if (name == "empty.test") {
        s.send(make_reply(q, dns::kNoError, {}), from);
    } else if (name == "tc.test") {
        s.send(make_reply(q, dns::kNoError, {ip(10, 0, 0, 9)}, true), from);
    } else if (name == "drop.test") {
        if (nth > 1) s.send(make_reply(q, dns::kNoError, {ip(10, 0, 0, 3)}), from);
    } else if (name == "fail.test") {
        s.send(make_reply(q, nth % 2 ? dns::kServFail : dns::kRefused, {}), from);
    } else if (name == "cname.test") {
        // cname.test CNAME a.test (fresh name at end of rdata), a.test A 10.0.0.7
        std::vector<uint8_t> b = make_reply(q, dns::kNoError, {});
        b[7] = 2;
        put_u16(b, 0xC00C);
        put_u16(b, dns::kTypeCname);
        put_u16(b, dns::kClassIn);
        put_u16(b, 0);
        put_u16(b, 60);
        put_u16(b, 8);
        const size_t target = b.size();
        const uint8_t a_test[8] = {1, 'a', 4, 't', 'e', 's', 't', 0};
        b.insert(b.end(), a_test, a_test + 8);
        put_u16(b, static_cast<uint16_t>(0xC000 | target));
        put_u16(b, dns::kTypeA);
        put_u16(b, dns::kClassIn);
        put_u16(b, 0);
        put_u16(b, 60);
        put_u16(b, 4);
        const uint8_t addr[4] = {10, 0, 0, 7};
        b.insert(b.end(), addr, addr + 4);
        s.send(b, from);
    } else if (name == "spoof.test") {
        // Three wrong replies (source, txid, question), garbage, then the real one.
        const auto good = make_reply(q, dns::kNoError, {ip(10, 0, 0, 4)});
        s.send_from_alt(make_reply(q, dns::kNoError, {ip(6, 6, 6, 6)}), from);
        auto wrong_id = make_reply(q, dns::kNoError, {ip(6, 6, 6, 6)});
        wrong_id[1] ^= 0x01;
        s.send(wrong_id, from);
        std::vector<uint8_t> other(dns::kMaxQuerySize);
        other.resize(dns::build_query(static_cast<uint16_t>((q[0] << 8) | q[1]), "spoof.tesu", dns::kTypeA,
                                      other.data(), other.size()));
        s.send(make_reply(other, dns::kNoError, {ip(6, 6, 6, 6)}), from);
        s.send({0xde, 0xad}, from);
        s.send(good, from);
    } else if (name == "alt-only.test") {
        s.send_from_alt(make_reply(q, dns::kNoError, {ip(6, 6, 6, 6)}), from);
    } else if (name == "formerr.test") {
        s.send(make_reply(q, has_edns(q) ? dns::kFormErr : dns::kNoError, {ip(10, 0, 0, 5)}), from);
    } else if (name == "wrongtype.test") {
        s.send(make_reply(with_qtype(q, dns::kTypeHttps), dns::kNoError, {}), from);
        s.send(make_reply(q, dns::kNoError, {ip(10, 0, 0, 6)}), from);
    } else if (name.rfind("q", 0) == 0) {  // q<N>.test -> 10.1.0.N
        s.send(make_reply(q, dns::kNoError, {ip(10, 1, 0, static_cast<uint8_t>(std::stoi(name.substr(1))))}), from);
    }
}

struct Result {
    bool done = false;
    Status status = Status::Invalid;
    uint32_t addr = 0;
};

dns::Resolver::Callback into(Result& r) {
    return [&r](Status status, uint32_t addr) {
        CHECK_FALSE(r.done);
        r.done = true;
        r.status = status;
        r.addr = addr;
    };
}

struct HttpsResult {
    bool done = false;
    Status status = Status::Invalid;
    dns::HttpsRecord record;
};

dns::Resolver::HttpsCallback into(HttpsResult& r) {
    return [&r](Status status, const dns::HttpsRecord& record) {
        CHECK_FALSE(r.done);
        r.done = true;
        r.status = status;
        r.record = record;
    };
}

bool run_until(net::Loop& loop, const std::function<bool()>& done, uint32_t timeout_ms = 3000) {
    bool timed_out = false;
    const net::TimerId watchdog = loop.add_timer(timeout_ms, [&] {
        timed_out = true;
        loop.stop();
    });
    net::TimerId poll_id = 0;
    std::function<void()> poll = [&] {
        if (done()) {
            loop.stop();
        } else {
            poll_id = loop.add_timer(1, poll);
        }
    };
    poll_id = loop.add_timer(0, poll);
    loop.run();
    loop.cancel_timer(poll_id);
    loop.cancel_timer(watchdog);
    return !timed_out;
}

template <typename R>
bool all_done(const std::vector<R>& results) {
    for (const R& r : results) {
        if (!r.done) return false;
    }
    return true;
}

dns::ResolverConfig config_for(std::initializer_list<const FakeDns*> servers, uint32_t timeout_ms, uint32_t attempts,
                               uint32_t max_inflight = 64) {
    dns::ResolverConfig c;
    for (const FakeDns* s : servers) c.servers.push_back(s->addr());
    c.timeout_ms = timeout_ms;
    c.attempts = attempts;
    c.max_inflight = max_inflight;
    return c;
}

void teardown(net::Loop& loop, dns::Resolver& resolver, std::initializer_list<FakeDns*> servers) {
    resolver.shutdown();
    for (FakeDns* s : servers) s->close();
    CHECK(run_until(loop, [&] {
        bool busy = resolver.busy();
        for (FakeDns* s : servers) busy = busy || s->busy();
        return !busy;
    }));
}

}  // namespace

TEST_CASE("resolver: answers, negative replies, literals and invalid names") {
    net::Loop loop;
    FakeDns server(loop, standard_behavior);
    dns::Resolver resolver(loop, config_for({&server}, 300, 2));
    REQUIRE(resolver.open_error() == 0);

    const char* hosts[] = {"a.test", "A.TEST.", "nx.test", "empty.test", "tc.test", "cname.test",
                           "192.0.2.33", "bad..name", "256.1.1.1"};
    std::vector<Result> results(std::size(hosts));
    for (size_t i = 0; i < results.size(); ++i) resolver.resolve(hosts[i], into(results[i]));
    for (const Result& r : results) CHECK_FALSE(r.done);  // never inline

    REQUIRE(run_until(loop, [&] { return all_done(results); }));
    CHECK(results[0].status == Status::Ok);
    CHECK(results[0].addr == ip(10, 0, 0, 1));
    CHECK(results[1].status == Status::Ok);
    CHECK(results[2].status == Status::NxDomain);
    CHECK(results[3].status == Status::NoAnswer);
    CHECK(results[4].status == Status::NoAnswer);
    CHECK(results[5].status == Status::Ok);
    CHECK(results[5].addr == ip(10, 0, 0, 7));
    CHECK(results[6].status == Status::Ok);
    CHECK(results[6].addr == ip(192, 0, 2, 33));
    CHECK(results[7].status == Status::Invalid);
    // Not a valid quad, but a valid DNS name: it goes to the server, which drops it.
    CHECK(results[8].status == Status::Timeout);

    const auto& c = resolver.counters();
    CHECK(c.ok == 3);  // literals are counted separately
    CHECK(c.nxdomain == 1);
    CHECK(c.noanswer == 2);
    CHECK(c.truncated == 1);
    CHECK(c.literals == 1);
    CHECK(c.invalid == 1);
    CHECK(c.timeouts == 1);
    CHECK(c.queries_sent == 8);  // 6 answered + 2 attempts for 256.1.1.1
    CHECK(c.mismatched == 0);
    CHECK(server.seen[1].name == "a.test");  // sent lowercased without the trailing dot
    teardown(loop, resolver, {&server});
}

TEST_CASE("resolver: SERVFAIL/REFUSED rotate servers; exhaustion is ServFail") {
    net::Loop loop;
    FakeDns failing(loop, [](FakeDns& s, const std::string&, int, const std::vector<uint8_t>& q,
                             const sockaddr_in& from) { s.send(make_reply(q, dns::kServFail, {}), from); });
    FakeDns good(loop, standard_behavior);
    dns::Resolver resolver(loop, config_for({&failing, &good}, 300, 3));

    Result rotated;
    resolver.resolve("a.test", into(rotated));  // first attempt goes to `failing`
    REQUIRE(run_until(loop, [&] { return rotated.done; }));
    CHECK(rotated.status == Status::Ok);
    CHECK(failing.seen.size() == 1);
    CHECK(good.seen.size() == 1);
    CHECK(resolver.counters().retries == 1);

    Result exhausted;
    resolver.resolve("fail.test", into(exhausted));  // good answers SERVFAIL then REFUSED
    REQUIRE(run_until(loop, [&] { return exhausted.done; }));
    CHECK(exhausted.status == Status::ServFail);
    CHECK(resolver.counters().queries_sent == 5);
    CHECK(resolver.counters().servfail == 1);
    teardown(loop, resolver, {&failing, &good});
}

TEST_CASE("resolver: dropped packet is retried, silence times out") {
    net::Loop loop;
    FakeDns server(loop, standard_behavior);
    dns::Resolver resolver(loop, config_for({&server}, 60, 3));

    Result dropped;
    Result silent;
    const uint64_t start = loop.now();
    resolver.resolve("drop.test", into(dropped));
    resolver.resolve("silent.test", into(silent));
    REQUIRE(run_until(loop, [&] { return dropped.done && silent.done; }));
    CHECK(dropped.status == Status::Ok);
    CHECK(dropped.addr == ip(10, 0, 0, 3));
    CHECK(silent.status == Status::Timeout);
    CHECK(loop.now() - start >= 3 * 60);

    const auto& c = resolver.counters();
    CHECK(c.queries_sent == 5);
    CHECK(c.retries == 3);
    CHECK(c.attempt_timeouts == 4);
    CHECK(c.timeouts == 1);
    // Retries reuse the transaction id.
    REQUIRE(server.seen.size() == 5);
    for (const auto& s : server.seen) {
        for (const auto& t : server.seen) {
            if (s.name == t.name) CHECK(s.id == t.id);
        }
    }
    teardown(loop, resolver, {&server});
}

TEST_CASE("resolver: rejects replies with wrong source, txid or question") {
    net::Loop loop;
    FakeDns server(loop, standard_behavior);
    dns::Resolver resolver(loop, config_for({&server}, 150, 1));

    Result spoofed;
    Result alt_only;
    resolver.resolve("spoof.test", into(spoofed));
    resolver.resolve("alt-only.test", into(alt_only));
    REQUIRE(run_until(loop, [&] {
        // The wrong-txid reply is normally "late" (txid not in flight) and only
        // "mismatched" if it happens to hit the other query's txid.
        const auto& c = resolver.counters();
        return spoofed.done && alt_only.done && c.mismatched + c.late == 4 &&
               resolver.counters().malformed == 1;
    }));
    CHECK(spoofed.status == Status::Ok);
    CHECK(spoofed.addr == ip(10, 0, 0, 4));
    CHECK(alt_only.status == Status::Timeout);
    teardown(loop, resolver, {&server});
}

TEST_CASE("resolver: max_inflight queues in FIFO order with unique txids") {
    net::Loop loop;
    FakeDns server(loop, standard_behavior);
    dns::Resolver resolver(loop, config_for({&server}, 500, 1, 3));

    std::vector<Result> results(12);
    for (size_t i = 0; i < results.size(); ++i) {
        resolver.resolve("q" + std::to_string(i) + ".test", into(results[i]));
    }
    CHECK(resolver.inflight() == 3);
    CHECK(resolver.queued() == 9);
    REQUIRE(run_until(loop, [&] { return all_done(results); }));
    for (size_t i = 0; i < results.size(); ++i) {
        CHECK(results[i].status == Status::Ok);
        CHECK(results[i].addr == ip(10, 1, 0, static_cast<uint8_t>(i)));
    }
    REQUIRE(server.seen.size() == results.size());
    for (size_t i = 0; i < results.size(); ++i) CHECK(server.seen[i].name == "q" + std::to_string(i) + ".test");
    CHECK(resolver.inflight() == 0);
    CHECK(resolver.queued() == 0);

    // Many concurrent queries: every in-flight txid is distinct.
    dns::Resolver wide(loop, config_for({&server}, 5000, 1, 300));
    std::vector<Result> silent(300);
    const size_t before = server.seen.size();
    for (size_t i = 0; i < silent.size(); ++i) wide.resolve("s" + std::to_string(i) + ".test", into(silent[i]));
    REQUIRE(run_until(loop, [&] { return server.seen.size() == before + silent.size(); }));
    std::set<uint16_t> ids;
    for (size_t i = before; i < server.seen.size(); ++i) ids.insert(server.seen[i].id);
    CHECK(ids.size() == silent.size());
    wide.shutdown();
    REQUIRE(run_until(loop, [&] { return all_done(silent) && !wide.busy(); }));
    teardown(loop, resolver, {&server});
}

TEST_CASE("resolver: shutdown fails pending and later requests with Timeout") {
    net::Loop loop;
    FakeDns server(loop, standard_behavior);
    dns::Resolver resolver(loop, config_for({&server}, 5000, 3, 2));

    std::vector<Result> results(4);
    for (Result& r : results) resolver.resolve("silent.test", into(r));
    CHECK(resolver.inflight() == 2);
    CHECK(resolver.queued() == 2);
    resolver.shutdown();
    CHECK(resolver.inflight() == 0);
    CHECK(resolver.queued() == 0);
    for (const Result& r : results) CHECK_FALSE(r.done);

    Result late;
    resolver.resolve("a.test", into(late));
    CHECK_FALSE(late.done);
    REQUIRE(run_until(loop, [&] { return all_done(results) && late.done && !resolver.busy(); }, 1000));
    for (const Result& r : results) CHECK(r.status == Status::Timeout);
    CHECK(late.status == Status::Timeout);
    CHECK(resolver.counters().cancelled == 5);
    teardown(loop, resolver, {&server});
}

TEST_CASE("resolver: callbacks may re-enter resolve and shutdown") {
    net::Loop loop;
    FakeDns server(loop, standard_behavior);
    dns::Resolver resolver(loop, config_for({&server}, 300, 1, 1));

    Result second;
    Result queued;
    Result first;
    resolver.resolve("a.test", [&](Status status, uint32_t) {
        first.done = true;
        first.status = status;
        resolver.resolve("nx.test", into(second));
    });
    resolver.resolve("q5.test", [&](Status status, uint32_t addr) {
        queued.done = true;
        queued.status = status;
        queued.addr = addr;
        resolver.shutdown();
    });
    REQUIRE(run_until(loop, [&] { return first.done && queued.done && second.done && !resolver.busy(); }));
    CHECK(first.status == Status::Ok);
    CHECK(queued.status == Status::Ok);
    // nx.test queued behind q5.test and was started before q5's callback ran;
    // the shutdown inside that callback cancels it.
    CHECK(second.status == Status::Timeout);
    REQUIRE(server.seen.size() >= 2);
    CHECK(server.seen[1].name == "q5.test");
    teardown(loop, resolver, {&server});
}

TEST_CASE("resolver: HTTPS records") {
    net::Loop loop;
    FakeDns server(loop, standard_behavior);
    dns::Resolver resolver(loop, config_for({&server}, 150, 2));

    const char* hosts[] = {"svc.test", "alias.test", "a.test",     "nx.test",   "bad.test",      "cname.test",
                           "tc.test",  "192.0.2.1",  "bad..name", "drop.test", "wrongtype.test"};
    std::vector<HttpsResult> results(std::size(hosts));
    for (size_t i = 0; i < results.size(); ++i) resolver.resolve_https(hosts[i], into(results[i]));
    // The same name through the A path at the same time.
    Result a;
    resolver.resolve("a.test", into(a));
    for (const HttpsResult& r : results) CHECK_FALSE(r.done);  // never inline

    REQUIRE(run_until(loop, [&] { return all_done(results) && a.done; }));
    CHECK(a.status == Status::Ok);
    CHECK(a.addr == ip(10, 0, 0, 1));

    const dns::HttpsRecord& svc = results[0].record;
    CHECK(results[0].status == Status::Ok);
    CHECK(svc.present);
    CHECK_FALSE(svc.alias_mode);
    CHECK(svc.priority == 1);
    CHECK(svc.target == ".");
    CHECK(svc.alpn_h3);
    CHECK(svc.alpn_h2);
    CHECK_FALSE(svc.alpn_http11);
    CHECK(svc.ech);
    CHECK(svc.ipv4hint);
    CHECK_FALSE(svc.ipv6hint);
    CHECK(svc.port == 0);
    CHECK(svc.rrset_size == 1);
    CHECK(svc.cname_hops == 0);

    CHECK(results[1].status == Status::Ok);
    CHECK(results[1].record.alias_mode);
    CHECK(results[1].record.priority == 0);
    CHECK(results[1].record.target == "cdn.example.net");

    CHECK(results[2].status == Status::NoAnswer);  // NODATA: no HTTPS record
    CHECK_FALSE(results[2].record.present);
    CHECK_FALSE(results[2].record.malformed);
    CHECK(results[3].status == Status::NxDomain);
    CHECK(results[4].status == Status::NoAnswer);
    CHECK_FALSE(results[4].record.present);
    CHECK(results[4].record.malformed);
    CHECK(results[5].status == Status::Ok);
    CHECK(results[5].record.cname_hops == 1);
    CHECK(results[5].record.alpn_h3);
    CHECK(results[6].status == Status::NoAnswer);  // truncated
    CHECK(results[7].status == Status::NoAnswer);  // IPv4 literal: no query
    CHECK_FALSE(results[7].record.present);
    CHECK(results[8].status == Status::Invalid);
    CHECK(results[9].status == Status::NoAnswer);  // dropped once, then NODATA
    CHECK(results[10].status == Status::Ok);       // after an A-typed reply was rejected
    CHECK(results[10].record.alias_mode);

    const auto& c = resolver.counters();
    CHECK(c.https_requests == results.size());
    CHECK(c.https_present == 4);
    CHECK(c.https_malformed == 1);
    CHECK(c.literals == 1);
    CHECK(c.invalid == 1);
    CHECK(c.truncated == 1);
    CHECK(c.mismatched == 1);
    CHECK(c.retries == 1);
    CHECK(c.ok == 5);  // 4 HTTPS + 1 A
    CHECK(c.queries_sent == 11);  // 9 HTTPS names + drop.test's retry + the A query

    size_t a_queries = 0;
    for (const auto& s : server.seen) {
        CAPTURE(s.name);
        CHECK(s.edns);  // every query carries the OPT record
        a_queries += s.qtype == dns::kTypeA;
    }
    CHECK(a_queries == 1);
    teardown(loop, resolver, {&server});
}

TEST_CASE("resolver: reply with the other query type is rejected") {
    net::Loop loop;
    FakeDns server(loop, standard_behavior);
    dns::Resolver resolver(loop, config_for({&server}, 300, 1));

    Result a;
    resolver.resolve("wrongtype.test", into(a));  // gets an HTTPS-typed reply first
    REQUIRE(run_until(loop, [&] { return a.done; }));
    CHECK(a.status == Status::Ok);
    CHECK(a.addr == ip(10, 0, 0, 6));
    CHECK(resolver.counters().mismatched == 1);
    teardown(loop, resolver, {&server});
}

TEST_CASE("resolver: FORMERR turns EDNS off for the remaining attempts") {
    net::Loop loop;
    FakeDns server(loop, standard_behavior);
    dns::Resolver resolver(loop, config_for({&server}, 300, 3));

    Result a;
    HttpsResult h;
    resolver.resolve("formerr.test", into(a));
    resolver.resolve_https("formerr.test", into(h));
    REQUIRE(run_until(loop, [&] { return a.done && h.done; }));
    CHECK(a.status == Status::Ok);
    CHECK(a.addr == ip(10, 0, 0, 5));
    CHECK(h.status == Status::Ok);
    CHECK(h.record.alpn_h3);
    CHECK(resolver.counters().edns_fallbacks == 2);
    CHECK(resolver.counters().retries == 2);
    REQUIRE(server.seen.size() == 4);
    for (uint16_t qtype : {dns::kTypeA, dns::kTypeHttps}) {
        std::vector<bool> edns;
        for (const auto& s : server.seen) {
            if (s.qtype == qtype) edns.push_back(s.edns);
        }
        CHECK(edns == std::vector<bool>{true, false});
    }

    // A single attempt has nothing to fall back to.
    dns::Resolver once(loop, config_for({&server}, 300, 1));
    Result failed;
    once.resolve("formerr.test", into(failed));
    REQUIRE(run_until(loop, [&] { return failed.done; }));
    CHECK(failed.status == Status::ServFail);
    once.shutdown();
    REQUIRE(run_until(loop, [&] { return !once.busy(); }));

    // EDNS configured off: plain queries from the first attempt.
    dns::ResolverConfig plain_config = config_for({&server}, 300, 1);
    plain_config.edns_udp_size = 0;
    dns::Resolver plain(loop, plain_config);
    Result direct;
    const size_t before = server.seen.size();
    plain.resolve("formerr.test", into(direct));
    REQUIRE(run_until(loop, [&] { return direct.done; }));
    CHECK(direct.status == Status::Ok);
    REQUIRE(server.seen.size() == before + 1);
    CHECK_FALSE(server.seen.back().edns);
    CHECK(plain.counters().edns_fallbacks == 0);
    plain.shutdown();
    REQUIRE(run_until(loop, [&] { return !plain.busy(); }));
    teardown(loop, resolver, {&server});
}

TEST_CASE("resolver: shutdown fails pending HTTPS lookups with Timeout") {
    net::Loop loop;
    FakeDns server(loop, standard_behavior);
    dns::Resolver resolver(loop, config_for({&server}, 5000, 3, 1));

    HttpsResult inflight;
    Result queued_a;
    HttpsResult queued_https;
    resolver.resolve_https("silent.test", into(inflight));
    resolver.resolve("silent.test", into(queued_a));
    resolver.resolve_https("silent.test", into(queued_https));
    CHECK(resolver.inflight() == 1);
    CHECK(resolver.queued() == 2);
    resolver.shutdown();

    HttpsResult late;
    resolver.resolve_https("svc.test", into(late));
    REQUIRE(run_until(loop, [&] {
        return inflight.done && queued_a.done && queued_https.done && late.done && !resolver.busy();
    }));
    for (const HttpsResult* r : {&inflight, &queued_https, &late}) {
        CHECK(r->status == Status::Timeout);
        CHECK_FALSE(r->record.present);
    }
    CHECK(queued_a.status == Status::Timeout);
    CHECK(resolver.counters().cancelled == 4);
    teardown(loop, resolver, {&server});
}

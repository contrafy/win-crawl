// benchsrv::build_dns_reply (the fake DNS server's own query codec) on
// arbitrary datagrams, cross-checked against wc::dns::parse_response.
//
// Invariants:
// - Drop exactly for datagrams shorter than a header or with QR set, and then
//   no reply bytes; otherwise a reply of at least a header that echoes the
//   id, has QR set and fits the 512-byte DnsServer slot;
// - Answered/NoData/NxDomain/Refused replies carry the query's question
//   verbatim; Answered ones parse with wc::dns (unless a label contains '.',
//   which wc::dns rejects by design) to exactly one A record equal to
//   host_ip() for the h<N> name, with the same question name.

#include "benchsrv/behavior.h"
#include "benchsrv/dns_server.h"
#include "dns/packet.h"

#include "check.h"

#include <cstring>
#include <vector>

using namespace wc;

namespace {

// Length of the uncompressed question name at query[12..], and whether any
// label contains a '.'; 0 if it is not well formed.
size_t question_name_len(const uint8_t* q, size_t len, bool& dotted) {
    dotted = false;
    size_t pos = 12;
    while (pos < len) {
        const uint8_t l = q[pos];
        if (l == 0) return pos + 1 - 12;
        if (l > 63 || pos + 1 + l > len) return 0;
        if (std::memchr(q + pos + 1, '.', l) != nullptr) dotted = true;
        pos += 1 + l;
    }
    return 0;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    static const benchsrv::Behavior behavior;  // defaults: zone bench.test
    // Exact-size copy so ASan catches reads past the datagram.
    const std::vector<char> query(data, data + size);
    std::vector<char> reply = {'j', 'u', 'n', 'k'};
    uint64_t delay_key = 1;
    const auto outcome = benchsrv::build_dns_reply(behavior, query.data(), query.size(), reply, delay_key);

    if (size < 12 || (data[2] & 0x80)) {
        FUZZ_CHECK(outcome == benchsrv::DnsOutcome::Drop);
    }
    if (outcome == benchsrv::DnsOutcome::Drop) {
        FUZZ_CHECK(reply.empty());
        return 0;
    }
    FUZZ_CHECK(reply.size() >= 12 && reply.size() <= 512);
    const auto* r = reinterpret_cast<const uint8_t*>(reply.data());
    FUZZ_CHECK(r[0] == data[0] && r[1] == data[1]);
    FUZZ_CHECK(r[2] & 0x80);
    if (outcome == benchsrv::DnsOutcome::Error) return 0;

    bool dotted = false;
    const size_t qlen = question_name_len(data, size, dotted);
    FUZZ_CHECK(qlen != 0 && 12 + qlen + 4 <= size);
    FUZZ_CHECK(reply.size() >= 12 + qlen + 4);
    FUZZ_CHECK(std::memcmp(r + 12, data + 12, qlen + 4) == 0);
    if (outcome != benchsrv::DnsOutcome::Answered || dotted) return 0;

    dns::Response parsed;
    FUZZ_CHECK(dns::parse_response(r, reply.size(), parsed));
    FUZZ_CHECK(parsed.qr && parsed.rcode == dns::kNoError);
    FUZZ_CHECK(parsed.addr_count == 1 && parsed.cname_hops == 0);
    const auto n = benchsrv::parse_host_name(parsed.question(), behavior.zone);
    FUZZ_CHECK(n.has_value());
    FUZZ_CHECK(*n == delay_key);
    FUZZ_CHECK(parsed.addrs[0] == benchsrv::host_ip(behavior, *n));
    return 0;
}

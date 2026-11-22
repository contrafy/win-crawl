#!/usr/bin/env python3
"""Summarize a wincrawl --record file (JSON lines) as a markdown report.

    python tools/study/analyze.py records.jsonl [--seeds N] [--title TEXT] [--top N]

Every share is printed with its numerator, denominator and a Wilson 95%
score interval. The record schema is documented in docs/study-method.md.
Standard library only.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from collections import Counter
from dataclasses import dataclass, field
from typing import Iterable, Iterator

Z95 = 1.959963984540054


def wilson(k: int, n: int, z: float = Z95) -> tuple[float, float]:
    """Wilson score interval for k successes out of n (as fractions)."""
    if n <= 0:
        return (0.0, 0.0)
    p = k / n
    z2 = z * z
    denom = 1 + z2 / n
    centre = (p + z2 / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z2 / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def share(k: int, n: int) -> str:
    """'k / n = p% [lo–hi]' or 'k / 0' when there is no denominator."""
    if n <= 0:
        return f"{k:,} / 0 (n/a)"
    lo, hi = wilson(k, n)
    return f"{k:,} / {n:,} = {100 * k / n:.2f}% [{100 * lo:.2f}–{100 * hi:.2f}]"


def read_records(path: str) -> Iterator[dict]:
    """Yields one dict per line; blank lines are skipped, bad lines are fatal."""
    with open(path, encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError as e:
                raise SystemExit(f"{path}:{lineno}: invalid JSON: {e}") from None
            if not isinstance(rec, dict) or "host" not in rec:
                raise SystemExit(f"{path}:{lineno}: not a wincrawl record")
            yield rec


def status_class(status: int | None) -> str:
    if status is None:
        return "none"
    if 100 <= status < 600:
        return f"{status // 100}xx"
    return "other"


def server_product(server: str) -> str:
    """'nginx/1.18.0 (Ubuntu)' -> 'nginx'; case-folded first product token."""
    s = server.strip()
    for sep in ("/", " ", "(", ";"):
        i = s.find(sep)
        if i > 0:
            s = s[:i]
    return s.lower() or "(empty)"


# HSTS max-age buckets: (label, exclusive upper bound in seconds).
HSTS_BUCKETS = [
    ("0 (delete)", 1),
    ("< 1 day", 86400),
    ("1 day – < 30 days", 30 * 86400),
    ("30 days – < 180 days", 180 * 86400),
    ("180 days – < 1 year", 31536000),
    ("1 year – < 2 years", 63072000),
    ("≥ 2 years", math.inf),
]


def hsts_bucket(max_age: int) -> str:
    for label, bound in HSTS_BUCKETS:
        if max_age < bound:
            return label
    return HSTS_BUCKETS[-1][0]


@dataclass
class Split:
    """Numerator/denominator pairs for one population (e.g. behind Cloudflare)."""

    https_sites: int = 0  # first TLS handshake completed (ok or certificate)
    tls13: int = 0
    pq: int = 0
    final_https: int = 0  # last page reply over https
    h3: int = 0
    hsts: int = 0
    rr_queried: int = 0
    rr_present: int = 0
    rr_h3: int = 0
    rr_ech: int = 0


@dataclass
class Stats:
    records: int = 0
    seed_https: int = 0
    dns: Counter = field(default_factory=Counter)
    dns_ok: int = 0
    unique_ips: int = 0
    ip_dup: int = 0
    robots_attempted: int = 0
    robots_replied: int = 0
    robots_allowed: int = 0
    robots_status: Counter = field(default_factory=Counter)
    robots_error: Counter = field(default_factory=Counter)
    page_attempted: int = 0
    page_replied: int = 0
    final_2xx: int = 0
    fetch: Counter = field(default_factory=Counter)
    status_class: Counter = field(default_factory=Counter)
    status: Counter = field(default_factory=Counter)
    redirects: Counter = field(default_factory=Counter)
    http_seed_replied: int = 0
    upgraded: int = 0
    alive: int = 0  # any HTTP reply (robots or page)
    # TLS
    tls_attempted: int = 0
    tls_handshake: Counter = field(default_factory=Counter)
    tls_version: Counter = field(default_factory=Counter)
    tls_cipher: Counter = field(default_factory=Counter)
    tls_group: Counter = field(default_factory=Counter)
    tls_with_version: int = 0
    tls13: int = 0
    tls13_group_known: int = 0
    pq_of_tls13: int = 0
    pq_known_sites: int = 0
    pq_sites: int = 0
    resumed: int = 0
    # Alt-Svc / HSTS on the last page reply
    final_https: int = 0
    final_any: int = 0
    h3_https: int = 0
    h3_any: int = 0
    hsts: int = 0
    hsts_valid: int = 0
    hsts_zero: int = 0
    hsts_sub: int = 0
    hsts_preload: int = 0
    hsts_age: Counter = field(default_factory=Counter)
    # HTTPS RR
    rr_status: Counter = field(default_factory=Counter)
    rr_queried: int = 0
    rr_present: int = 0
    rr_alias: int = 0
    rr_h3: int = 0
    rr_h2: int = 0
    rr_ech: int = 0
    # Cloudflare
    cf_ip_known: int = 0
    cf_ip: int = 0
    cf_ray_known: int = 0
    cf_ray: int = 0
    cf_both_known: int = 0
    cf_agree: Counter = field(default_factory=Counter)  # (cf_ip, cf_ray) -> n
    cf_any: int = 0
    by_cf: dict = field(default_factory=lambda: {True: Split(), False: Split()})
    # Misc
    server: Counter = field(default_factory=Counter)
    server_raw: Counter = field(default_factory=Counter)
    servers_seen: int = 0
    content_type: Counter = field(default_factory=Counter)
    ms: list = field(default_factory=list)


def analyze(records: Iterable[dict]) -> Stats:
    s = Stats()
    for r in records:
        s.records += 1
        url = r.get("url") or ""
        if url.lower().startswith("https://"):
            s.seed_https += 1
        dns = r.get("dns") or "none"
        s.dns[dns] += 1
        if dns == "ok":
            s.dns_ok += 1
            if r.get("ip_dup") is False:
                s.unique_ips += 1
            elif r.get("ip_dup") is True:
                s.ip_dup += 1

        rs, re_ = r.get("robots_status"), r.get("robots_error")
        if rs is not None or re_ is not None or r.get("robots_allowed") is not None:
            s.robots_attempted += 1
        if rs is not None:
            s.robots_replied += 1
            s.robots_status[status_class(rs)] += 1
        if re_ is not None:
            s.robots_error[re_] += 1
        if r.get("robots_allowed") is True:
            s.robots_allowed += 1

        fetch = r.get("fetch")
        status = r.get("status")
        if fetch is not None:
            s.page_attempted += 1
            s.fetch[fetch] += 1
            s.redirects[r.get("redirects") or 0] += 1
        if status is not None:
            s.page_replied += 1
            s.status_class[status_class(status)] += 1
            s.status[status] += 1
            if 200 <= status < 300:
                s.final_2xx += 1
            if not url.lower().startswith("https://"):
                s.http_seed_replied += 1
                if r.get("https_upgrade") is True:
                    s.upgraded += 1
        if rs is not None or status is not None:
            s.alive += 1

        # TLS: first handshake of the site.
        tls = r.get("tls")
        behind_cf = r.get("cf_ip") is True or r.get("cf_ray") is True
        split = s.by_cf[behind_cf]
        if tls is not None:
            s.tls_attempted += 1
            s.tls_handshake[tls.get("handshake") or "none"] += 1
            version = tls.get("version")
            if version:
                s.tls_with_version += 1
                s.tls_version[version] += 1
                split.https_sites += 1
                if tls.get("cipher"):
                    s.tls_cipher[tls["cipher"]] += 1
                group = tls.get("group")
                s.tls_group[group or "(unknown)"] += 1
                pq = tls.get("pq")
                if pq is not None:
                    s.pq_known_sites += 1
                    if pq:
                        s.pq_sites += 1
                        split.pq += 1
                if version == "TLS 1.3":
                    s.tls13 += 1
                    split.tls13 += 1
                    if pq is not None:
                        s.tls13_group_known += 1
                        if pq:
                            s.pq_of_tls13 += 1
                if tls.get("resumed") is True:
                    s.resumed += 1

        # Last page reply: Alt-Svc, HSTS.
        if status is not None:
            s.final_any += 1
            final_https = (r.get("final_url") or "").lower().startswith("https://")
            if r.get("alt_svc_h3") is True:
                s.h3_any += 1
            if final_https:
                s.final_https += 1
                split.final_https += 1
                if r.get("alt_svc_h3") is True:
                    s.h3_https += 1
                    split.h3 += 1
                if r.get("hsts") is True:
                    s.hsts += 1
                    split.hsts += 1
                    age = r.get("hsts_max_age")
                    if age is not None:
                        s.hsts_valid += 1
                        s.hsts_age[hsts_bucket(age)] += 1
                        if age == 0:
                            s.hsts_zero += 1
                        else:
                            if r.get("hsts_sub") is True:
                                s.hsts_sub += 1
                            if r.get("hsts_preload") is True:
                                s.hsts_preload += 1

        # HTTPS RR.
        rr = r.get("https_rr")
        if rr is not None:
            s.rr_status[rr.get("status") or "none"] += 1
            if rr.get("status") != "cancelled":
                s.rr_queried += 1
                split.rr_queried += 1
                if rr.get("present"):
                    s.rr_present += 1
                    split.rr_present += 1
                    s.rr_alias += bool(rr.get("alias"))
                    s.rr_h2 += bool(rr.get("h2"))
                    if rr.get("h3"):
                        s.rr_h3 += 1
                        split.rr_h3 += 1
                    if rr.get("ech"):
                        s.rr_ech += 1
                        split.rr_ech += 1

        # Cloudflare.
        cf_ip, cf_ray = r.get("cf_ip"), r.get("cf_ray")
        if cf_ip is not None:
            s.cf_ip_known += 1
            s.cf_ip += cf_ip is True
        if cf_ray is not None:
            s.cf_ray_known += 1
            s.cf_ray += cf_ray is True
        if cf_ip is not None and cf_ray is not None:
            s.cf_both_known += 1
            s.cf_agree[(cf_ip, cf_ray)] += 1
        if behind_cf:
            s.cf_any += 1

        server = r.get("server")
        if server is not None:
            s.servers_seen += 1
            s.server[server_product(server)] += 1
            s.server_raw[server] += 1
        ct = r.get("content_type")
        if ct is not None and status is not None and 200 <= status < 300:
            s.content_type[ct.split(";")[0].strip().lower() or "(empty)"] += 1
        if r.get("ms") is not None:
            s.ms.append(r["ms"])
    return s


def percentile(sorted_values: list, q: float) -> float:
    if not sorted_values:
        return 0.0
    i = min(len(sorted_values) - 1, max(0, math.ceil(q * len(sorted_values)) - 1))
    return sorted_values[i]


class Md:
    def __init__(self) -> None:
        self.lines: list[str] = []

    def h(self, level: int, text: str) -> None:
        self.lines += ["", "#" * level + " " + text, ""]

    def p(self, text: str) -> None:
        self.lines += [text, ""]

    def table(self, header: list[str], rows: list[list]) -> None:
        self.lines.append("| " + " | ".join(header) + " |")
        self.lines.append("|" + "|".join("---" for _ in header) + "|")
        for row in rows:
            self.lines.append("| " + " | ".join(str(c) for c in row) + " |")
        self.lines.append("")

    def counter_table(self, title: str, counter: Counter, n: int, top: int | None = None) -> None:
        items = counter.most_common(top)
        rows = [[f"`{k}`" if k != "" else "(empty)", share(v, n)] for k, v in items]
        if top is not None and len(counter) > top:
            rest = sum(counter.values()) - sum(v for _, v in items)
            rows.append([f"({len(counter) - top} others)", share(rest, n)])
        if not rows:
            rows.append(["(none)", "—"])
        self.table([title, "share"], rows)

    def text(self) -> str:
        while self.lines and self.lines[0] == "":
            self.lines.pop(0)
        return "\n".join(self.lines).rstrip() + "\n"


def render(s: Stats, seeds: int | None = None, title: str = "wincrawl measurement report", top: int = 15) -> str:
    md = Md()
    md.h(1, title)
    md.p(
        "Shares are `numerator / denominator = percent [Wilson 95% interval]`. "
        "One record per unique host attempted (seed URLs that passed host dedupe)."
    )

    md.h(2, "Funnel")
    rows = []
    if seeds is not None:
        rows.append(["seed URLs", f"{seeds:,}", ""])
        rows.append(["unique hosts", f"{s.records:,}", share(s.records, seeds)])
    else:
        rows.append(["unique hosts", f"{s.records:,}", ""])
    rows += [
        ["DNS ok", f"{s.dns_ok:,}", share(s.dns_ok, s.records)],
        ["unique IPs (passed IP dedupe)", f"{s.unique_ips:,}", share(s.unique_ips, s.dns_ok)],
        ["robots.txt attempted", f"{s.robots_attempted:,}", share(s.robots_attempted, s.unique_ips)],
        ["robots.txt allowed the page", f"{s.robots_allowed:,}", share(s.robots_allowed, s.robots_attempted)],
        ["page fetch attempted", f"{s.page_attempted:,}", share(s.page_attempted, s.robots_allowed)],
        ["page reply received", f"{s.page_replied:,}", share(s.page_replied, s.page_attempted)],
        ["final reply 2xx", f"{s.final_2xx:,}", share(s.final_2xx, s.page_replied)],
    ]
    md.table(["stage", "count", "of previous stage"], rows)
    if s.seed_https:
        md.p(f"Seeds with an https:// URL: {share(s.seed_https, s.records)} of unique hosts.")

    md.h(2, "Link rot")
    dead_dns = s.dns["nxdomain"] + s.dns["noanswer"]
    connect = s.robots_error["connect_fail"]
    md.table(
        ["outcome", "share of unique hosts"],
        [
            ["NXDOMAIN (name gone)", share(s.dns["nxdomain"], s.records)],
            ["no A record (NOERROR/NODATA)", share(s.dns["noanswer"], s.records)],
            ["SERVFAIL / REFUSED", share(s.dns["servfail"], s.records)],
            ["DNS timeout", share(s.dns["timeout"], s.records)],
            ["resolves, but TCP connect fails (first request)", share(connect, s.records)],
            ["resolves, but first request times out", share(s.robots_error["timeout"], s.records)],
            ["**dead: NXDOMAIN + no A + connect failure**", share(dead_dns + connect, s.records)],
            ["alive: any HTTP reply (robots or page)", share(s.alive, s.records)],
        ],
    )
    md.p(
        "IP-duplicate hosts are not fetched, so 'alive' is bounded by unique IPs; "
        f"{share(s.alive, s.unique_ips)} of hosts that passed IP dedupe answered HTTP."
    )
    md.counter_table("DNS status", s.dns, s.records)

    md.h(2, "Redirects and HTTPS upgrade")
    md.p(
        "http:// seeds whose last page reply came over https (redirected to https): "
        f"{share(s.upgraded, s.http_seed_replied)} of http seeds with a page reply."
    )
    md.table(
        ["redirects followed", "share of page fetches"],
        [[k, share(v, s.page_attempted)] for k, v in sorted(s.redirects.items())],
    )
    md.counter_table("page fetch outcome", s.fetch, s.page_attempted)

    md.h(2, "Status codes")
    md.counter_table("final status class", s.status_class, s.page_replied)
    md.counter_table("final status", s.status, s.page_replied, top)
    md.counter_table("robots.txt status class", s.robots_status, s.robots_replied)
    md.counter_table("robots.txt fetch error", s.robots_error, s.robots_attempted)

    md.h(2, "TLS")
    md.p(
        "First TLS handshake of each site (the first https connection, robots.txt or page). "
        f"Sites that reached a TLS handshake: {s.tls_attempted:,}."
    )
    md.counter_table("handshake outcome", s.tls_handshake, s.tls_attempted)
    md.counter_table("version", s.tls_version, s.tls_with_version)
    md.counter_table("key exchange group", s.tls_group, s.tls_with_version, top)
    md.counter_table("cipher suite", s.tls_cipher, s.tls_with_version, top)
    md.table(
        ["post-quantum hybrid key exchange", "share"],
        [
            ["of TLS 1.3 handshakes", share(s.pq_of_tls13, s.tls13_group_known)],
            ["of all https sites (handshake completed)", share(s.pq_sites, s.pq_known_sites)],
        ],
    )
    if s.tls13 != s.tls13_group_known:
        md.p(f"({s.tls13 - s.tls13_group_known:,} TLS 1.3 handshakes have no group recorded and are excluded.)")
    md.p(f"Resumed handshakes: {share(s.resumed, s.tls_with_version)}.")

    md.h(2, "HTTP/3 (Alt-Svc) and HSTS")
    md.table(
        ["fact", "share"],
        [
            ["Alt-Svc advertises h3, of last replies over https", share(s.h3_https, s.final_https)],
            ["Alt-Svc advertises h3, of all last replies", share(s.h3_any, s.final_any)],
            ["HSTS header, of last replies over https", share(s.hsts, s.final_https)],
            ["HSTS valid (parsable max-age), of HSTS headers", share(s.hsts_valid, s.hsts)],
            ["max-age=0 (asks to forget HSTS), of valid", share(s.hsts_zero, s.hsts_valid)],
            ["includeSubDomains, of valid with max-age > 0", share(s.hsts_sub, s.hsts_valid - s.hsts_zero)],
            ["preload, of valid with max-age > 0", share(s.hsts_preload, s.hsts_valid - s.hsts_zero)],
        ],
    )
    md.table(
        ["HSTS max-age", "share of valid HSTS"],
        [[label, share(s.hsts_age[label], s.hsts_valid)] for label, _ in HSTS_BUCKETS],
    )

    md.h(2, "HTTPS DNS records (RFC 9460)")
    if s.rr_queried == 0 and not s.rr_status:
        md.p("Not measured (run with `--https-rr`).")
    else:
        md.p(f"Queried for every host whose A lookup succeeded; cancelled queries excluded ({s.rr_queried:,} answered).")
        md.counter_table("HTTPS query status", s.rr_status, sum(s.rr_status.values()))
        md.table(
            ["fact", "share"],
            [
                ["HTTPS RR present, of queried", share(s.rr_present, s.rr_queried)],
                ["AliasMode, of present", share(s.rr_alias, s.rr_present)],
                ["alpn includes h3, of present", share(s.rr_h3, s.rr_present)],
                ["alpn includes h2, of present", share(s.rr_h2, s.rr_present)],
                ["ECH config, of present", share(s.rr_ech, s.rr_present)],
                ["ECH config, of queried", share(s.rr_ech, s.rr_queried)],
            ],
        )

    md.h(2, "Cloudflare")
    a = s.cf_agree
    md.table(
        ["signal", "share"],
        [
            ["IP in Cloudflare's published ranges, of resolved hosts", share(s.cf_ip, s.cf_ip_known)],
            ["CF-RAY header on the first reply, of hosts with a reply", share(s.cf_ray, s.cf_ray_known)],
            ["either signal (\"behind Cloudflare\"), of unique hosts", share(s.cf_any, s.records)],
            ["signals agree, of hosts with both known", share(a[(True, True)] + a[(False, False)], s.cf_both_known)],
        ],
    )
    md.table(
        ["", "CF-RAY yes", "CF-RAY no"],
        [
            ["IP in CF ranges", f"{a[(True, True)]:,}", f"{a[(True, False)]:,}"],
            ["IP not in CF ranges", f"{a[(False, True)]:,}", f"{a[(False, False)]:,}"],
        ],
    )
    cf, other = s.by_cf[True], s.by_cf[False]
    md.table(
        ["fact", "behind Cloudflare", "not behind Cloudflare"],
        [
            ["TLS 1.3, of completed handshakes", share(cf.tls13, cf.https_sites), share(other.tls13, other.https_sites)],
            ["PQ hybrid, of TLS 1.3 handshakes", share(cf.pq, cf.tls13), share(other.pq, other.tls13)],
            ["PQ hybrid, of completed handshakes", share(cf.pq, cf.https_sites), share(other.pq, other.https_sites)],
            ["Alt-Svc h3, of last replies over https", share(cf.h3, cf.final_https), share(other.h3, other.final_https)],
            ["HSTS, of last replies over https", share(cf.hsts, cf.final_https), share(other.hsts, other.final_https)],
            ["HTTPS RR present, of queried", share(cf.rr_present, cf.rr_queried), share(other.rr_present, other.rr_queried)],
            ["HTTPS RR with ECH, of queried", share(cf.rr_ech, cf.rr_queried), share(other.rr_ech, other.rr_queried)],
        ],
    )

    md.h(2, "Servers and content")
    md.counter_table("Server header (product token)", s.server, s.servers_seen, top)
    md.counter_table("Server header (verbatim)", s.server_raw, s.servers_seen, top)
    md.counter_table("Content-Type of 2xx replies", s.content_type, sum(s.content_type.values()), top)

    if s.ms:
        ms = sorted(s.ms)
        md.h(2, "Time per site")
        md.table(
            ["p50", "p90", "p99", "max"],
            [[f"{percentile(ms, q):,.0f} ms" for q in (0.5, 0.9, 0.99)] + [f"{ms[-1]:,} ms"]],
        )
    return md.text()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("records", help="wincrawl --record output (JSON lines)")
    ap.add_argument("--seeds", type=int, help="seed URL count (input lines) for the first funnel row")
    ap.add_argument("--title", default="wincrawl measurement report")
    ap.add_argument("--top", type=int, default=15, help="rows in top-N tables (default 15)")
    args = ap.parse_args(argv)
    stats = analyze(read_records(args.records))
    # The report uses en dashes and ≥; Windows consoles default to a legacy code page.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    sys.stdout.write(render(stats, seeds=args.seeds, title=args.title, top=args.top))
    return 0


if __name__ == "__main__":
    sys.exit(main())

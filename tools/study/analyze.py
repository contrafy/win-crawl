#!/usr/bin/env python3
"""Summarize a wincrawl --record file (JSON lines) as a markdown report.

    python tools/study/analyze.py records.jsonl [--seeds N] [--title TEXT] [--top N]

Every share is printed with its numerator, denominator and a Wilson 95%
score interval. With a per-IP host budget (--hosts-per-ip; 1 is the
assignment's IP dedupe) hosts on busy IPs are sampled, so the HTTP and TLS
facts are also reported weighted by inverse sampling probability per IP
(resolving hosts on the IP / fetched hosts on the IP). The record schema is
documented in docs/study-method.md, the weighting in docs/politeness.md.
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


# Crawl-delay buckets: (label, inclusive upper bound in seconds).
CRAWL_DELAY_BUCKETS = [("0", 0), ("(0, 1]", 1), ("(1, 5]", 5), ("(5, 10]", 10), ("(10, 30]", 30),
                       ("(30, 60]", 60), ("> 60", math.inf)]


def crawl_delay_bucket(seconds: float) -> str:
    for label, bound in CRAWL_DELAY_BUCKETS:
        if seconds <= bound:
            return label
    return CRAWL_DELAY_BUCKETS[-1][0]


def sampled(r: dict) -> bool:
    """The host was fetched: it resolved, was within its IP's host budget and
    its IP was not skipped as unreachable. These hosts carry the HTTP/TLS
    facts; the other resolving hosts of an IP are represented through the
    IP's weight."""
    return r.get("dns") == "ok" and r.get("ip_dup") is False and r.get("skip") not in ("ip_budget", "ip_unreachable")


def _tls_version(r: dict):
    t = r.get("tls")
    return t.get("version") if t else None


def _pq(r: dict):
    t = r.get("tls")
    return t.get("pq") if t else None


def _replied_https(r: dict) -> bool:
    return r.get("status") is not None and (r.get("final_url") or "").lower().startswith("https://")


# HTTP/TLS facts of fetched hosts, reported unweighted and IP-weighted:
# (label, in the denominator?, in the numerator?).
FACTS = [
    ("any HTTP reply (robots or page), of fetched hosts",
     lambda r: True, lambda r: r.get("robots_status") is not None or r.get("status") is not None),
    ("robots.txt allowed the page, of fetched hosts", lambda r: True, lambda r: r.get("robots_allowed") is True),
    ("final reply 2xx, of page replies",
     lambda r: r.get("status") is not None, lambda r: 200 <= r["status"] < 300),
    ("http seed ends on https, of http seeds with a page reply",
     lambda r: r.get("status") is not None and not (r.get("url") or "").lower().startswith("https://"),
     lambda r: r.get("https_upgrade") is True),
    ("TLS 1.3, of completed handshakes", lambda r: _tls_version(r) is not None, lambda r: _tls_version(r) == "TLS 1.3"),
    ("PQ hybrid, of TLS 1.3 handshakes",
     lambda r: _tls_version(r) == "TLS 1.3" and _pq(r) is not None, lambda r: _pq(r) is True),
    ("PQ hybrid, of completed handshakes",
     lambda r: _tls_version(r) is not None and _pq(r) is not None, lambda r: _pq(r) is True),
    ("Alt-Svc h3, of last replies over https", _replied_https, lambda r: r.get("alt_svc_h3") is True),
    ("HSTS, of last replies over https", _replied_https, lambda r: r.get("hsts") is True),
    ("CF-RAY on the first reply, of hosts with a reply",
     lambda r: r.get("cf_ray") is not None, lambda r: r.get("cf_ray") is True),
]


@dataclass
class IpTally:
    """One IP: its resolving and fetched hosts and the fact counts of the latter."""

    resolving: int = 0
    fetched: int = 0
    cf: bool = False
    den: list = field(default_factory=lambda: [0] * len(FACTS))
    num: list = field(default_factory=lambda: [0] * len(FACTS))


@dataclass
class Weighted:
    """A fact over fetched hosts: plain counts, and IP-weighted sums with the
    Kish effective sample size of the weighted denominator."""

    k: int = 0
    n: int = 0
    wk: float = 0.0
    wn: float = 0.0
    w2n: float = 0.0  # sum of squared weights over the denominator

    @property
    def share(self) -> float:
        return self.wk / self.wn if self.wn > 0 else 0.0

    @property
    def n_eff(self) -> float:
        return self.wn * self.wn / self.w2n if self.w2n > 0 else 0.0


def weighted_share(w: Weighted) -> str:
    """'p% [lo–hi], n_eff N': the weighted share with a Wilson interval on the
    effective sample size."""
    if w.wn <= 0:
        return "n/a"
    lo, hi = wilson(w.share * w.n_eff, w.n_eff)
    return f"{100 * w.share:.2f}% [{100 * lo:.2f}–{100 * hi:.2f}], n_eff {w.n_eff:,.0f}"


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
    fetched: int = 0     # sampled(): within the per-IP host budget and attempted
    unique_ips: int = 0  # distinct IPs among fetched hosts
    ip_dup: int = 0      # over the per-IP host budget (ip_dup true)
    skip: Counter = field(default_factory=Counter)
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
    # Per-IP sampling (IP-weighted facts, coverage)
    ips: dict = field(default_factory=dict)  # ip -> IpTally
    facts: list = field(default_factory=lambda: [Weighted() for _ in FACTS])
    unweightable: int = 0  # fetched hosts' IPs whose weight is unknown (no IP recorded)
    # Politeness (records written by builds with docs/politeness.md)
    wait_ms: list = field(default_factory=list)
    crawl_delay: Counter = field(default_factory=Counter)
    crawl_delay_robots: int = 0  # fetched hosts whose robots.txt answered 2xx
    retry_after: int = 0
    retried: int = 0


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
            if r.get("ip_dup") is True:
                s.ip_dup += 1
            ip = r.get("ip")
            tally = s.ips.get(ip) if ip is not None else None
            if tally is None and ip is not None:
                tally = s.ips[ip] = IpTally()
            if tally is not None:
                tally.resolving += 1
                tally.cf = tally.cf or r.get("cf_ip") is True
            if sampled(r):
                s.fetched += 1
                if tally is None:
                    s.unweightable += 1
                else:
                    tally.fetched += 1
                    for i, (_, in_den, in_num) in enumerate(FACTS):
                        if in_den(r):
                            tally.den[i] += 1
                            if in_num(r):
                                tally.num[i] += 1
                if r.get("wait_ms") is not None:
                    s.wait_ms.append(r["wait_ms"])
                rs_ = r.get("robots_status")
                if rs_ is not None and 200 <= rs_ < 300:
                    s.crawl_delay_robots += 1
                    if r.get("crawl_delay") is not None:
                        s.crawl_delay[crawl_delay_bucket(r["crawl_delay"])] += 1
                if r.get("retry_after") is not None:
                    s.retry_after += 1
                    s.retried += r.get("retried") is True
        if r.get("skip") is not None:
            s.skip[r["skip"]] += 1

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
    # Inverse-probability weights: each fetched host stands for its IP's
    # resolving hosts divided by the IP's fetched hosts.
    for tally in s.ips.values():
        if tally.fetched == 0:
            continue
        s.unique_ips += 1
        w = tally.resolving / tally.fetched
        for i, f in enumerate(s.facts):
            d = tally.den[i]
            if d:
                k = tally.num[i]
                f.k += k
                f.n += d
                f.wk += w * k
                f.wn += w * d
                f.w2n += w * w * d
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


def render_coverage(md: Md, s: Stats) -> None:
    """Coverage of resolving hosts, the IP-weighted facts, and politeness."""
    md.h(2, "Coverage and per-IP sampling")
    tallies = list(s.ips.values())
    cf = [t for t in tallies if t.cf]
    other = [t for t in tallies if not t.cf]
    shared = [t for t in tallies if t.resolving >= 2]
    md.table(
        ["population", "fetched / resolving hosts"],
        [
            ["all resolving hosts", share(s.fetched, s.dns_ok)],
            ["on Cloudflare IPs (published ranges)", share(sum(t.fetched for t in cf), sum(t.resolving for t in cf))],
            ["on other IPs", share(sum(t.fetched for t in other), sum(t.resolving for t in other))],
            ["on IPs with 2+ resolving hosts", share(sum(t.fetched for t in shared), sum(t.resolving for t in shared))],
        ],
    )
    biggest = max(tallies, key=lambda t: t.resolving, default=None)
    uncovered = sum(t.resolving for t in tallies if t.fetched == 0)
    text = f"{len(tallies):,} IPs resolved, {s.unique_ips:,} with at least one host fetched"
    if biggest is not None:
        text += f"; the largest carries {biggest.resolving:,} resolving hosts ({biggest.fetched:,} fetched)"
    text += f". Resolving hosts on IPs with no host fetched (no weight possible): {uncovered:,}."
    md.p(text)
    if s.skip:
        md.counter_table("skipped by politeness (`skip`)", s.skip, s.dns_ok)

    md.h(2, "HTTP and TLS facts, IP-weighted")
    md.p(
        "A per-IP host budget samples hosts on shared IPs. Each fetched host is weighted by its IP's "
        "resolving hosts / fetched hosts, so every resolving host counts once (inverse-probability "
        "weighting); intervals use the Kish effective sample size. With one host per IP (the "
        "assignment's IP dedupe) the unweighted column describes the first host on each IP."
    )
    md.table(
        ["fact", "unweighted", "IP-weighted"],
        [[label, share(f.k, f.n), weighted_share(f)] for (label, _, _), f in zip(FACTS, s.facts)],
    )
    if s.unweightable:
        md.p(f"({s.unweightable:,} fetched hosts have no IP recorded and are left out of both columns.)")

    if not (s.wait_ms or s.skip or s.crawl_delay or s.retry_after):
        return
    md.h(2, "Politeness")
    waits = sorted(s.wait_ms)
    if waits:
        waited = sum(1 for w in waits if w > 0)
        md.p(f"Fetched hosts that waited on politeness (IP queue and spacing, Crawl-delay, Retry-After): "
             f"{share(waited, len(waits))}.")
        md.table(
            ["wait per fetched host", "p50", "p90", "p99", "max"],
            [[""] + [f"{percentile(waits, q):,.0f} ms" for q in (0.5, 0.9, 0.99)] + [f"{waits[-1]:,} ms"]],
        )
    md.p(f"robots.txt with a Crawl-delay, of fetched hosts whose robots.txt answered 2xx: "
         f"{share(sum(s.crawl_delay.values()), s.crawl_delay_robots)}.")
    if s.crawl_delay:
        md.table(
            ["Crawl-delay (s)", "share of robots.txt with one"],
            [[label, share(s.crawl_delay[label], sum(s.crawl_delay.values()))] for label, _ in CRAWL_DELAY_BUCKETS],
        )
    md.p(f"429/503 replies with a Retry-After: {s.retry_after:,}; retried after waiting it out: "
         f"{share(s.retried, s.retry_after)}.")


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
        ["fetched (within the per-IP host budget)", f"{s.fetched:,}", share(s.fetched, s.dns_ok)],
        ["robots.txt attempted", f"{s.robots_attempted:,}", share(s.robots_attempted, s.fetched)],
        ["robots.txt allowed the page", f"{s.robots_allowed:,}", share(s.robots_allowed, s.robots_attempted)],
        ["page fetch attempted", f"{s.page_attempted:,}", share(s.page_attempted, s.robots_allowed)],
        ["page reply received", f"{s.page_replied:,}", share(s.page_replied, s.page_attempted)],
        ["final reply 2xx", f"{s.final_2xx:,}", share(s.final_2xx, s.page_replied)],
    ]
    md.table(["stage", "count", "of previous stage"], rows)
    md.p(f"Distinct IPs among fetched hosts: {s.unique_ips:,}.")
    if s.seed_https:
        md.p(f"Seeds with an https:// URL: {share(s.seed_https, s.records)} of unique hosts.")

    render_coverage(md, s)

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
            ["resolves, IP skipped after repeated failures (not attempted)", share(s.skip["ip_unreachable"], s.records)],
            ["**dead: NXDOMAIN + no A + connect failure**", share(dead_dns + connect, s.records)],
            ["alive: any HTTP reply (robots or page)", share(s.alive, s.records)],
        ],
    )
    md.p(
        "Hosts over their IP's host budget are not fetched, so 'alive' is bounded by fetched hosts; "
        f"{share(s.alive, s.fetched)} of fetched hosts answered HTTP."
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
            ["either signal (\"behind Cloudflare\"), of resolved hosts", share(s.cf_any, s.dns_ok)],
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

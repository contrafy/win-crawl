#!/usr/bin/env python3
"""Estimate coverage and wall time of a polite no-dedupe study from a record file.

    python tools/study/estimate.py study.jsonl [policy options] [--sweep 1,100,1000,0]

Reads any wincrawl --record file (e.g. the published 1M study, which fetched
one host per IP) for the hosts-per-IP distribution and each IP's outcome, and
models a rerun under a politeness policy (docs/politeness.md):

- an IP's fetched hosts are min(resolving hosts, --hosts-per-ip) (CDN IPs use
  --cdn-hosts-per-ip, 0 = unlimited);
- an IP drains at min(concurrency / site time, 1 / (connections per site *
  interval)) sites per second; an IP whose sampled host was refused or timed
  out stops after --ip-fail-limit failures;
- the rest of the crawl is bound by the uplink: a fixed part plus a cost per
  fetched site, calibrated on the published runs (classic 1M: ~160 s; real
  mode: 422 s for 113,963 fetched sites, so ~2.3 ms of uplink per site);
- wall time = max(uplink time, slowest IP) + a tail.

Site times come from the live validation run in docs/politeness.md. It is a
model: use it to compare policies, not as a promise. Standard library only.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from collections import Counter
from dataclasses import dataclass, field
from typing import Iterable


@dataclass
class Model:
    hosts_per_ip: int = 1           # 0 = unlimited
    ip_concurrency: int = 2         # 0 = unlimited
    ip_interval_ms: int = 250
    cdn_hosts_per_ip: int | None = None  # None: 1 with hosts_per_ip 1, else unlimited (the crawler's rule)
    cdn_ip_concurrency: int = 16
    cdn_ip_interval_ms: int = 0
    ip_fail_limit: int = 5
    max_ip_penalty_ms: int = 10000
    # Seconds a site holds its IP's connection slot, by how the sampled host
    # answered (live validation run, docs/politeness.md).
    tls_site_s: float = 1.8
    http_site_s: float = 1.2
    refused_s: float = 2.0   # Windows retries a refused SYN for ~2 s
    timeout_s: float = 10.0  # --timeout
    # Uplink: fixed seconds (DNS for every host, ramp) + per fetched site.
    fixed_s: float = 160.0
    site_cost_ms: float = 2.3
    tail_s: float = 20.0

    def budget(self, cdn: bool) -> int:
        if not cdn:
            return self.hosts_per_ip
        if self.cdn_hosts_per_ip is not None:
            return self.cdn_hosts_per_ip
        return 1 if self.hosts_per_ip == 1 else 0


@dataclass
class Ip:
    resolving: int = 0
    cf: bool = False
    replied: bool = False   # some fetched host got an HTTP reply other than 429/503
    throttled: bool = False  # some fetched host got 429/503
    tls: bool = False       # ... over https
    redirected: bool = False
    failed: str | None = None  # "refused" / "timeout" when no fetched host replied


def read_ips(records: Iterable[dict]) -> dict:
    """Per IP: resolving hosts, Cloudflare range, and how its fetched hosts answered."""
    ips: dict = {}
    for r in records:
        if r.get("dns") != "ok" or r.get("ip") is None:
            continue
        ip = ips.setdefault(r["ip"], Ip())
        ip.resolving += 1
        ip.cf = ip.cf or r.get("cf_ip") is True
        if r.get("ip_dup") is not False or r.get("skip") in ("ip_budget", "ip_unreachable", "ip_throttled", "stopped"):
            continue
        statuses = [x for x in (r.get("robots_status"), r.get("status")) if x is not None]
        if any(x in (429, 503) for x in statuses):
            ip.throttled = True
        if any(x not in (429, 503) for x in statuses):
            ip.replied = True
            ip.tls = ip.tls or r.get("tls") is not None
            ip.redirected = ip.redirected or bool(r.get("redirects"))
        elif not statuses and r.get("robots_error") in ("connect_fail", "timeout") and ip.failed is None:
            ip.failed = "refused" if r["robots_error"] == "connect_fail" else "timeout"
    return ips


@dataclass
class Estimate:
    resolving: Counter = field(default_factory=Counter)  # "cf" / "other" -> hosts
    fetched: Counter = field(default_factory=Counter)
    uplink_s: float = 0.0
    slowest_s: float = 0.0
    slowest: list = field(default_factory=list)  # (seconds, ip, fetched, resolving)
    wall_s: float = 0.0

    def coverage(self, key: str | None = None) -> float:
        res = sum(self.resolving.values()) if key is None else self.resolving[key]
        got = sum(self.fetched.values()) if key is None else self.fetched[key]
        return got / res if res else 0.0


def estimate(ips: dict, m: Model, top: int = 5) -> Estimate:
    e = Estimate()
    drains = []
    for addr, ip in ips.items():
        cdn = ip.cf
        budget = m.budget(cdn)
        conc = m.cdn_ip_concurrency if cdn else m.ip_concurrency
        interval = (m.cdn_ip_interval_ms if cdn else m.ip_interval_ms) / 1000.0
        attempted = ip.resolving if budget == 0 else min(ip.resolving, budget)
        # The breakers stop an ordinary IP after fail_limit failures (plus what
        # was already in flight); CDN edges are exempt.
        breaker = m.ip_fail_limit and not cdn
        cap = m.ip_fail_limit + max(conc, 1) - 1 if breaker else attempted
        if not ip.replied and ip.throttled:
            # Only 429/503: every start waits out the (capped) penalty.
            attempted = min(attempted, cap)
            rate = 1.0 / (interval + m.max_ip_penalty_ms / 1000.0) if not cdn else (conc / m.http_site_s if conc else math.inf)
        elif not ip.replied and ip.failed is not None:
            attempted = min(attempted, cap)
            per = m.refused_s if ip.failed == "refused" else m.timeout_s
            rate = (conc / per) if conc else math.inf
        else:
            per = m.tls_site_s if ip.tls else m.http_site_s
            starts = 2.0 if ip.redirected else 1.0  # a redirect to https or another host opens a new connection
            rate = min(conc / per if conc else math.inf, 1.0 / (starts * interval) if interval else math.inf)
        seconds = attempted / rate if rate != math.inf else 0.0
        key = "cf" if cdn else "other"
        e.resolving[key] += ip.resolving
        e.fetched[key] += attempted
        drains.append((seconds, addr, attempted, ip.resolving))
    drains.sort(reverse=True)
    e.slowest = drains[:top]
    e.slowest_s = drains[0][0] if drains else 0.0
    e.uplink_s = m.fixed_s + sum(e.fetched.values()) * m.site_cost_ms / 1000.0
    e.wall_s = max(e.uplink_s, e.slowest_s) + m.tail_s
    return e


def report(ips: dict, base: Model, budgets: list[int]) -> str:
    lines = [
        f"{len(ips):,} IPs, {sum(i.resolving for i in ips.values()):,} resolving hosts. Policy: "
        f"{base.ip_concurrency} connections / {base.ip_interval_ms} ms per IP; CDN "
        f"{base.cdn_ip_concurrency} / {base.cdn_ip_interval_ms} ms; breakers after {base.ip_fail_limit}; "
        f"429/503 penalty up to {base.max_ip_penalty_ms} ms.",
        "",
        "| --hosts-per-ip | fetched hosts | coverage | CF coverage | non-CF coverage | uplink s | slowest IP s | est. wall |",
        "|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for b in budgets:
        m = Model(**{**base.__dict__, "hosts_per_ip": b})
        e = estimate(ips, m)
        lines.append(
            f"| {b if b else 'unlimited'} | {sum(e.fetched.values()):,} | {100 * e.coverage():.1f}% | "
            f"{100 * e.coverage('cf'):.1f}% | {100 * e.coverage('other'):.1f}% | {e.uplink_s:,.0f} | "
            f"{e.slowest_s:,.0f} | {e.wall_s / 60:,.1f} min |"
        )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("records", help="wincrawl --record output (JSON lines)")
    d = Model()
    ap.add_argument("--hosts-per-ip", type=int, default=d.hosts_per_ip, help="0 = unlimited (default 1, as wincrawl)")
    ap.add_argument("--ip-concurrency", type=int, default=d.ip_concurrency)
    ap.add_argument("--ip-interval", type=int, default=d.ip_interval_ms)
    ap.add_argument("--cdn-hosts-per-ip", type=int, default=None)
    ap.add_argument("--cdn-ip-concurrency", type=int, default=d.cdn_ip_concurrency)
    ap.add_argument("--cdn-ip-interval", type=int, default=d.cdn_ip_interval_ms)
    ap.add_argument("--ip-fail-limit", type=int, default=d.ip_fail_limit)
    ap.add_argument("--max-ip-penalty", type=int, default=d.max_ip_penalty_ms)
    ap.add_argument("--tls-site-s", type=float, default=d.tls_site_s)
    ap.add_argument("--http-site-s", type=float, default=d.http_site_s)
    ap.add_argument("--sweep", help="comma-separated --hosts-per-ip values for a table (0 = unlimited)")
    args = ap.parse_args(argv)
    m = Model(hosts_per_ip=args.hosts_per_ip, ip_concurrency=args.ip_concurrency, ip_interval_ms=args.ip_interval,
              cdn_hosts_per_ip=args.cdn_hosts_per_ip, cdn_ip_concurrency=args.cdn_ip_concurrency,
              cdn_ip_interval_ms=args.cdn_ip_interval, ip_fail_limit=args.ip_fail_limit,
              max_ip_penalty_ms=args.max_ip_penalty, tls_site_s=args.tls_site_s, http_site_s=args.http_site_s)
    with open(args.records, encoding="utf-8") as f:
        ips = read_ips(json.loads(line) for line in f if line.strip())
    if args.sweep:
        sys.stdout.write(report(ips, m, [int(x) for x in args.sweep.split(",")]))
        return 0
    e = estimate(ips, m)
    print(f"fetched {sum(e.fetched.values()):,} of {sum(e.resolving.values()):,} resolving hosts "
          f"({100 * e.coverage():.1f}%; Cloudflare {100 * e.coverage('cf'):.1f}%, other {100 * e.coverage('other'):.1f}%)")
    print(f"uplink-bound part {e.uplink_s:,.0f} s, slowest IP {e.slowest_s:,.0f} s -> about {e.wall_s / 60:,.1f} min")
    for seconds, addr, got, res in e.slowest:
        print(f"  {addr}: {got:,} of {res:,} hosts, {seconds:,.0f} s")
    return 0


if __name__ == "__main__":
    sys.exit(main())

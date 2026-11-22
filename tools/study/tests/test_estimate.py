"""Unit tests for tools/study/estimate.py.

    python -m unittest discover -s tools/study/tests
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import estimate  # noqa: E402


def rec(ip: str, dup: bool, cf: bool = False, **fields) -> dict:
    r = {"dns": "ok", "ip": ip, "ip_dup": dup, "cf_ip": cf, "robots_status": None, "robots_error": None,
         "status": None, "redirects": None, "tls": None}
    r.update(fields)
    return r


# The published study's shape: one fetched host per IP, the rest ip_dup.
RECORDS = (
    # 100 hosts on a plain-http origin.
    [rec("1.1.1.1", False, robots_status=404, status=200, redirects=0)] + [rec("1.1.1.1", True)] * 99
    # 10 hosts on a refusing IP.
    + [rec("2.2.2.2", False, robots_error="connect_fail")] + [rec("2.2.2.2", True)] * 9
    # 30 hosts on a Cloudflare IP, served over TLS after a redirect.
    + [rec("104.16.0.1", False, cf=True, robots_status=200, status=200, redirects=1, tls={"version": "TLS 1.3"})]
    + [rec("104.16.0.1", True, cf=True)] * 29
    # Not resolving: ignored.
    + [{"dns": "nxdomain", "ip": None}]
)


class EstimateTest(unittest.TestCase):
    def setUp(self):
        self.ips = estimate.read_ips(RECORDS)

    def test_read_ips(self):
        self.assertEqual(len(self.ips), 3)
        a, b, c = self.ips["1.1.1.1"], self.ips["2.2.2.2"], self.ips["104.16.0.1"]
        self.assertEqual((a.resolving, a.replied, a.tls, a.redirected), (100, True, False, False))
        self.assertEqual((b.resolving, b.replied, b.failed), (10, False, "refused"))
        self.assertEqual((c.resolving, c.cf, c.tls, c.redirected), (30, True, True, True))

    def test_dedupe_policy_reproduces_the_published_shape(self):
        e = estimate.estimate(self.ips, estimate.Model(hosts_per_ip=1))
        self.assertEqual(sum(e.fetched.values()), 3)  # one per IP, CDN included
        self.assertAlmostEqual(e.coverage(), 3 / 140)

    def test_no_dedupe(self):
        m = estimate.Model(hosts_per_ip=0, ip_concurrency=2, ip_interval_ms=250, http_site_s=1.0, ip_fail_limit=5,
                           fixed_s=0, site_cost_ms=0, tail_s=0)
        e = estimate.estimate(self.ips, m)
        # http origin: min(2 / 1.0 s, 1 / 0.25 s) = 2 sites/s -> 100 hosts in 50 s.
        self.assertEqual(e.slowest[0][1], "1.1.1.1")
        self.assertAlmostEqual(e.slowest_s, 50.0)
        # The refusing IP stops after 5 + 1 attempts; the CDN IP takes all 30.
        self.assertEqual(e.fetched["other"], 100 + 6)
        self.assertEqual(e.fetched["cf"], 30)
        self.assertAlmostEqual(e.wall_s, 50.0)

    def test_budget_caps_the_slowest_ip(self):
        m = estimate.Model(hosts_per_ip=20, http_site_s=1.0, fixed_s=0, site_cost_ms=0, tail_s=0)
        e = estimate.estimate(self.ips, m)
        self.assertAlmostEqual(e.slowest_s, 10.0)
        self.assertEqual(e.fetched["cf"], 30)  # CDN IPs: unlimited unless --hosts-per-ip is 1

    def test_throttling_ip(self):
        # 50 hosts on an IP whose sampled host got 429: each start waits out
        # the capped penalty until the throttle breaker stops it.
        records = [rec("9.9.9.9", False, robots_status=429)] + [rec("9.9.9.9", True)] * 49
        ips = estimate.read_ips(records)
        self.assertTrue(ips["9.9.9.9"].throttled)
        self.assertFalse(ips["9.9.9.9"].replied)
        m = estimate.Model(hosts_per_ip=0, ip_interval_ms=250, max_ip_penalty_ms=10000, ip_fail_limit=5,
                           fixed_s=0, site_cost_ms=0, tail_s=0)
        e = estimate.estimate(ips, m)
        self.assertEqual(e.fetched["other"], 6)  # 5 + the one in flight
        self.assertAlmostEqual(e.slowest_s, 6 * 10.25)
        # Without the breaker it would drain at one host per 10.25 s.
        m.ip_fail_limit = 0
        self.assertAlmostEqual(estimate.estimate(ips, m).slowest_s, 50 * 10.25)

    def test_cdn_ip_has_no_breaker(self):
        records = [rec("104.16.0.2", False, cf=True, robots_error="connect_fail")] + \
                  [rec("104.16.0.2", True, cf=True)] * 39
        e = estimate.estimate(estimate.read_ips(records), estimate.Model(hosts_per_ip=0))
        self.assertEqual(e.fetched["cf"], 40)

    def test_cli_sweep(self):
        fd, path = tempfile.mkstemp(suffix=".jsonl")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            for r in RECORDS:
                f.write(json.dumps(r) + "\n")
        try:
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(estimate.main([path, "--sweep", "1,0"]), 0)
            text = out.getvalue()
            self.assertIn("| 1 | 3 | 2.1% |", text)
            self.assertIn("| unlimited | 136 |", text)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()

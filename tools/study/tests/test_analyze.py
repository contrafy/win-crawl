"""Unit tests for tools/study/analyze.py on a tiny synthetic record file.

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

import analyze  # noqa: E402


def record(host: str, **fields) -> dict:
    """A record with every field null except url/host/ms, then `fields`."""
    r = {
        "url": f"http://{host}/",
        "host": host,
        "dns": None,
        "ip": None,
        "ip_dup": None,
        "cf_ip": None,
        "https_rr": None,
        "robots_status": None,
        "robots_error": None,
        "robots_allowed": None,
        "fetch": None,
        "status": None,
        "redirects": None,
        "final_url": None,
        "https_upgrade": None,
        "tls": None,
        "alt_svc_h3": None,
        "hsts": None,
        "hsts_max_age": None,
        "hsts_sub": None,
        "hsts_preload": None,
        "server": None,
        "cf_ray": None,
        "content_type": None,
        "bytes": None,
        "links": None,
        "ms": 10,
    }
    r.update(fields)
    return r


def tls(version="TLS 1.3", group="X25519MLKEM768", pq=True, handshake="ok"):
    return {"handshake": handshake, "version": version, "cipher": "TLS_AES_128_GCM_SHA256", "group": group,
            "pq": pq, "resumed": False}


def rr(present=True, h3=True, ech=False, status="ok"):
    return {"status": status, "present": present, "alias": False, "h3": h3, "h2": present, "ech": ech}


RESOLVED = {"dns": "ok", "ip_dup": False, "cf_ip": False}

RECORDS = [
    # 1. NXDOMAIN.
    record("gone.test", dns="nxdomain"),
    # 2. No A record.
    record("noa.test", dns="noanswer"),
    # 3. IP duplicate of a later host.
    record("dup.test", dns="ok", ip="1.2.3.4", ip_dup=True, cf_ip=False, https_rr=rr(present=False, h3=False,
                                                                                       status="noanswer")),
    # 4. Resolves, connect fails.
    record("dead.test", **RESOLVED, ip="10.0.0.1", robots_error="connect_fail", robots_allowed=False),
    # 5. Behind Cloudflare (both signals), upgraded to https, PQ, h3, HSTS 1 year + preload, ECH.
    record("cf.test", dns="ok", ip="104.16.0.1", ip_dup=False, cf_ip=True, cf_ray=True,
           https_rr=rr(ech=True), robots_status=404, robots_allowed=True, fetch="ok", status=200, redirects=1,
           final_url="https://cf.test/", https_upgrade=True, tls=tls(), alt_svc_h3=True, hsts=True,
           hsts_max_age=31536000, hsts_sub=True, hsts_preload=True, server="cloudflare",
           content_type="text/html; charset=utf-8", bytes=100, links=3),
    # 6. Not Cloudflare, upgraded to https over TLS 1.2 (secp256r1), no h3, HSTS max-age=0.
    record("plain.test", **RESOLVED, ip="5.6.7.8", robots_status=200, robots_allowed=True, fetch="ok",
           status=200, redirects=1, final_url="https://plain.test/", https_upgrade=True,
           tls=tls(version="TLS 1.2", group="secp256r1", pq=False), alt_svc_h3=False, hsts=True, hsts_max_age=0,
           hsts_sub=False, hsts_preload=False, server="nginx/1.18.0 (Ubuntu)", cf_ray=False,
           content_type="text/html", https_rr=rr(present=False, h3=False, status="noanswer")),
    # 7. Stays on http, 404, Server header shared with #6's product.
    record("http.test", **RESOLVED, ip="5.6.7.9", robots_status=404, robots_allowed=True, fetch="ok",
           status=404, redirects=0, final_url="http://http.test/", https_upgrade=False, alt_svc_h3=False,
           server="nginx", cf_ray=False, https_rr=rr(present=False, h3=False, status="noanswer")),
    # 8. CF-RAY without a Cloudflare IP (disagreement), robots disallows.
    record("ray.test", **RESOLVED, ip="9.9.9.9", cf_ray=True, robots_status=200, robots_allowed=False,
           https_rr=rr(present=True, h3=False, status="ok")),
]


class WilsonTest(unittest.TestCase):
    def test_known_values(self):
        lo, hi = analyze.wilson(0, 10)
        self.assertAlmostEqual(lo, 0.0, places=6)
        self.assertAlmostEqual(hi, 0.27753, places=4)
        lo, hi = analyze.wilson(5, 10)
        self.assertAlmostEqual(lo, 0.23659, places=4)
        self.assertAlmostEqual(hi, 0.76341, places=4)
        lo, hi = analyze.wilson(10, 10)
        self.assertAlmostEqual(hi, 1.0, places=6)
        self.assertEqual(analyze.wilson(0, 0), (0.0, 0.0))

    def test_share_format(self):
        self.assertEqual(analyze.share(5, 10), "5 / 10 = 50.00% [23.66–76.34]")
        self.assertEqual(analyze.share(1234, 0), "1,234 / 0 (n/a)")

    def test_helpers(self):
        self.assertEqual(analyze.server_product("nginx/1.18.0 (Ubuntu)"), "nginx")
        self.assertEqual(analyze.server_product("Microsoft-IIS/10.0"), "microsoft-iis")
        self.assertEqual(analyze.server_product("  "), "(empty)")
        self.assertEqual(analyze.hsts_bucket(0), "0 (delete)")
        self.assertEqual(analyze.hsts_bucket(31536000), "1 year – < 2 years")
        self.assertEqual(analyze.hsts_bucket(63072000), "≥ 2 years")
        self.assertEqual(analyze.status_class(301), "3xx")
        self.assertEqual(analyze.status_class(None), "none")
        self.assertEqual(analyze.status_class(999), "other")


class AnalyzeTest(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".jsonl")
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            for r in RECORDS:
                f.write(json.dumps(r) + "\n")
            f.write("\n")  # blank lines are tolerated

    def tearDown(self):
        os.unlink(self.path)

    def test_counts(self):
        s = analyze.analyze(analyze.read_records(self.path))
        self.assertEqual(s.records, 8)
        self.assertEqual(s.dns_ok, 6)
        self.assertEqual(s.unique_ips, 5)
        self.assertEqual(s.robots_attempted, 5)
        self.assertEqual(s.robots_allowed, 3)
        self.assertEqual(s.page_attempted, 3)
        self.assertEqual(s.page_replied, 3)
        self.assertEqual(s.final_2xx, 2)
        self.assertEqual(s.alive, 4)
        self.assertEqual((s.http_seed_replied, s.upgraded), (3, 2))
        # TLS
        self.assertEqual(s.tls_with_version, 2)
        self.assertEqual(s.tls13, 1)
        self.assertEqual((s.pq_of_tls13, s.tls13_group_known), (1, 1))
        self.assertEqual((s.pq_sites, s.pq_known_sites), (1, 2))
        # Alt-Svc / HSTS (last reply over https: cf.test, plain.test)
        self.assertEqual((s.h3_https, s.final_https), (1, 2))
        self.assertEqual((s.h3_any, s.final_any), (1, 3))
        self.assertEqual((s.hsts, s.hsts_valid, s.hsts_zero), (2, 2, 1))
        self.assertEqual((s.hsts_sub, s.hsts_preload), (1, 1))
        # HTTPS RR
        self.assertEqual((s.rr_present, s.rr_queried), (2, 5))
        self.assertEqual((s.rr_h3, s.rr_ech), (1, 1))
        # Cloudflare
        self.assertEqual((s.cf_ip, s.cf_ip_known), (1, 6))
        self.assertEqual((s.cf_ray, s.cf_ray_known), (2, 4))
        self.assertEqual(s.cf_both_known, 4)
        self.assertEqual(s.cf_agree[(True, True)], 1)
        self.assertEqual(s.cf_agree[(False, True)], 1)
        self.assertEqual(s.cf_agree[(False, False)], 2)
        self.assertEqual(s.cf_any, 2)
        self.assertEqual(s.by_cf[True].pq, 1)
        self.assertEqual(s.by_cf[False].https_sites, 1)
        self.assertEqual(s.server["nginx"], 2)

    def test_report(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(analyze.main([self.path, "--seeds", "10", "--title", "Synthetic"]), 0)
        text = out.getvalue()
        self.assertTrue(text.startswith("# Synthetic\n"))
        for fragment in [
            "| seed URLs | 10 |  |",
            "| unique hosts | 8 | 8 / 10 = 80.00% [49.02–94.33] |",
            "| DNS ok | 6 | 6 / 8 = 75.00%",
            "| **dead: NXDOMAIN + no A + connect failure** | 3 / 8 = 37.50%",
            "redirected to https): 2 / 3 = 66.67%",
            "| of TLS 1.3 handshakes | 1 / 1 = 100.00%",
            "| of all https sites (handshake completed) | 1 / 2 = 50.00%",
            "| Alt-Svc advertises h3, of last replies over https | 1 / 2 = 50.00%",
            "| HTTPS RR present, of queried | 2 / 5 = 40.00%",
            "| signals agree, of hosts with both known | 3 / 4 = 75.00%",
            "| IP in CF ranges | 1 | 0 |",
            "| IP not in CF ranges | 1 | 2 |",
            "| `nginx` | 2 / 3 = 66.67%",
            "| 1 year – < 2 years | 1 / 2 = 50.00%",
        ]:
            self.assertIn(fragment, text)
        # Markdown tables: every table row has the header's column count.
        for line in text.splitlines():
            if line.startswith("|"):
                self.assertTrue(line.endswith("|"), line)

    def test_rejects_bad_lines(self):
        with open(self.path, "a", encoding="utf-8") as f:
            f.write("{not json\n")
        with self.assertRaises(SystemExit) as ctx:
            analyze.analyze(analyze.read_records(self.path))
        self.assertIn(":10: invalid JSON", str(ctx.exception))

    def test_empty_file(self):
        with open(self.path, "w", encoding="utf-8"):
            pass
        text = analyze.render(analyze.analyze(analyze.read_records(self.path)))
        self.assertIn("| unique hosts | 0 |", text)
        self.assertIn("Not measured (run with `--https-rr`).", text)


if __name__ == "__main__":
    unittest.main()

"""Deterministic offline unit tests for ssl_probe.py."""

from __future__ import annotations

import csv
import io
import json
import socket
import ssl
import tempfile
import unittest
import urllib.error
from datetime import datetime, timedelta, timezone
from pathlib import Path

import ssl_probe as sp


class _FakeSocket:
    def __init__(self) -> None:
        self.closed = False

    def __enter__(self) -> "_FakeSocket":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.closed = True


class _FakeTlsSocket:
    def __init__(self, cert: dict | None) -> None:
        self._cert = cert

    def __enter__(self) -> "_FakeTlsSocket":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None

    def getpeercert(self) -> dict | None:
        return self._cert


class _FakeSslContext:
    def __init__(self, cert: dict | None = None, error: Exception | None = None) -> None:
        self._cert = cert
        self._error = error

    def wrap_socket(self, sock: object, server_hostname: str | None = None) -> _FakeTlsSocket:
        if self._error is not None:
            raise self._error
        return _FakeTlsSocket(self._cert)


class _FakeUrllibResponse:
    def __init__(self, status: int, body: bytes, headers: dict[str, str] | None = None) -> None:
        self.status = status
        self._body = body
        self.headers = _SimpleHeaders(headers or {})

    def __enter__(self) -> "_FakeUrllibResponse":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None

    def read(self) -> bytes:
        return self._body

    def getcode(self) -> int:
        return self.status


class _SimpleHeaders:
    def __init__(self, mapping: dict[str, str]) -> None:
        self._mapping = mapping

    def items(self):
        return self._mapping.items()


class SslProbeTests(unittest.TestCase):
    FIXED_NOW = datetime(2026, 11, 19, 12, 0, 0, tzinfo=timezone.utc)

    def test_compute_percentile_single_and_multiple(self) -> None:
        self.assertIsNone(sp.compute_percentile([], 50))
        self.assertEqual(sp.compute_percentile([42.346], 95), 42.35)
        self.assertEqual(sp.compute_percentile([30.0, 10.0, 20.0], 50), 20.0)
        self.assertEqual(sp.compute_percentile([10.0, 20.0, 30.0], 95), 29.0)
        self.assertEqual(sp.compute_percentile([10.0, 20.0, 30.0, 40.0], 50), 25.0)
        self.assertEqual(sp.compute_percentile([10.0, 20.0, 30.0, 40.0], 95), 38.5)
        with self.assertRaises(ValueError):
            sp.compute_percentile([10.0], 101)

    def test_parse_expected_status_variants(self) -> None:
        self.assertIsNone(sp.parse_expected_status(None))
        self.assertIsNone(sp.parse_expected_status("  "))
        self.assertEqual(sp.parse_expected_status(200), (200,))
        self.assertEqual(sp.parse_expected_status("200, 204"), (200, 204))
        self.assertEqual(sp.parse_expected_status([200, 201, 204]), (200, 201, 204))
        for bad in (True, "abc", 99, 600, [200, "201"]):
            with self.assertRaises(ValueError):
                sp.parse_expected_status(bad)

    def test_validate_url_http_https_ipv6_and_invalid(self) -> None:
        self.assertEqual(sp.validate_url("https://api.example.com/health"), ("https", "api.example.com", 443))
        self.assertEqual(sp.validate_url("http://localhost:8080/readyz"), ("http", "localhost", 8080))
        self.assertEqual(sp.validate_url("https://[::1]:8443/ping"), ("https", "::1", 8443))
        for bad in ("", "ftp://example.com", "https:///no-host", "example.com/path"):
            with self.assertRaises(ValueError):
                sp.validate_url(bad)

    def test_inspect_ssl_certificate_healthy_with_mock_socket(self) -> None:
        expiry_dt = self.FIXED_NOW + timedelta(days=45)
        not_after_str = expiry_dt.strftime("%b %d %H:%M:%S %Y GMT")
        cert = {
            "notAfter": not_after_str,
            "subject": ((("commonName", "api.example.com"),),),
            "issuer": ((("commonName", "Example CA"),), (("organizationName", "Example Trust"),)),
        }
        calls: list[tuple[tuple[str, int], float]] = []

        def fake_connector(addr, timeout=5.0):
            calls.append((addr, timeout))
            return _FakeSocket()

        info = sp.inspect_ssl_certificate(
            "api.example.com",
            443,
            timeout=3.5,
            now=self.FIXED_NOW,
            socket_connector=fake_connector,
            ssl_context_factory=lambda: _FakeSslContext(cert=cert),
        )
        self.assertIsNone(info.error)
        self.assertEqual(info.days_remaining, 45.0)
        self.assertEqual(info.not_after, "2027-01-03T12:00:00Z")
        self.assertEqual(info.subject, "CN=api.example.com")
        self.assertEqual(info.issuer, "CN=Example CA, O=Example Trust")
        self.assertEqual(calls, [(("api.example.com", 443), 3.5)])

    def test_inspect_ssl_certificate_handles_socket_timeout_and_ssl_error(self) -> None:
        def timeout_connector(addr, timeout=5.0):
            raise TimeoutError("timed out")

        err_timeout = sp.inspect_ssl_certificate(
            "api.example.com",
            443,
            now=self.FIXED_NOW,
            socket_connector=timeout_connector,
            ssl_context_factory=lambda: _FakeSslContext(cert={}),
        )
        self.assertIsNone(err_timeout.days_remaining)
        self.assertIn("TimeoutError", err_timeout.error or "")

        err_ssl = sp.inspect_ssl_certificate(
            "api.example.com",
            443,
            now=self.FIXED_NOW,
            socket_connector=lambda addr, timeout=5.0: _FakeSocket(),
            ssl_context_factory=lambda: _FakeSslContext(error=ssl.SSLError("certificate verify failed")),
        )
        self.assertIsNone(err_ssl.days_remaining)
        self.assertIn("SSLError", err_ssl.error or "")

    def test_inspect_ssl_certificate_missing_not_after(self) -> None:
        info = sp.inspect_ssl_certificate(
            "api.example.com",
            443,
            now=self.FIXED_NOW,
            socket_connector=lambda addr, timeout=5.0: _FakeSocket(),
            ssl_context_factory=lambda: _FakeSslContext(cert={"subject": ()}),
        )
        self.assertIsNone(info.days_remaining)
        self.assertIn("notAfter", info.error or "")

    def test_fetch_http_once_success_and_timing(self) -> None:
        ticks = iter([10.000, 10.0375])
        target = sp.ProbeTarget(url="https://api.example.com/health", headers={"X-Probe": "1"})

        def fake_urlopen(req, timeout=5.0):
            self.assertEqual(req.get_header("X-probe"), "1")
            self.assertEqual(timeout, 5.0)
            return _FakeUrllibResponse(200, b'{"status":"ok"}', {"Content-Type": "application/json"})

        resp = sp.fetch_http_once(target, urlopen_fn=fake_urlopen, timer=lambda: next(ticks))
        self.assertIsNone(resp.error)
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.body, b'{"status":"ok"}')
        self.assertEqual(resp.latency_ms, 37.5)
        self.assertEqual(resp.headers.get("Content-Type"), "application/json")

    def test_fetch_http_once_http_error_extracts_code_and_body(self) -> None:
        ticks = iter([1.000, 1.015])
        target = sp.ProbeTarget(url="https://api.example.com/health")

        def fake_urlopen(req, timeout=5.0):
            fp = io.BytesIO(b"upstream maintenance")
            raise urllib.error.HTTPError(
                req.full_url,
                503,
                "Service Unavailable",
                hdrs=_SimpleHeaders({"Retry-After": "30"}),
                fp=fp,
            )

        resp = sp.fetch_http_once(target, urlopen_fn=fake_urlopen, timer=lambda: next(ticks))
        self.assertIsNone(resp.error)
        self.assertEqual(resp.status, 503)
        self.assertEqual(resp.body, b"upstream maintenance")
        self.assertEqual(resp.latency_ms, 15.0)

    def test_fetch_http_once_url_error_and_timeout(self) -> None:
        ticks = iter([5.0, 5.5, 6.0, 7.0])
        target = sp.ProbeTarget(url="https://api.example.com/health")

        resp_url_err = sp.fetch_http_once(
            target,
            urlopen_fn=lambda r, timeout=5.0: (_ for _ in ()).throw(urllib.error.URLError("Connection refused")),
            timer=lambda: next(ticks),
        )
        self.assertIsNone(resp_url_err.status)
        self.assertIn("URLError", resp_url_err.error or "")
        self.assertEqual(resp_url_err.latency_ms, 500.0)

        resp_timeout = sp.fetch_http_once(
            target,
            urlopen_fn=lambda r, timeout=5.0: (_ for _ in ()).throw(socket.timeout("timed out")),
            timer=lambda: next(ticks),
        )
        self.assertIsNone(resp_timeout.status)
        self.assertIn("TimeoutError", resp_timeout.error or "")

    def test_probe_target_healthy_https_with_p50_p95_and_keyword(self) -> None:
        latencies = iter([10.0, 20.0, 30.0, 40.0, 100.0])
        target = sp.ProbeTarget(
            name="Core API",
            url="https://api.example.com/health",
            samples=5,
            expected_status=(200,),
            keyword='"status":"ok"',
            warn_p95_ms=200.0,
        )

        def fake_fetch(_target):
            return sp.HttpResponse(status=200, body=b'{"status":"ok"}', latency_ms=next(latencies))

        def fake_ssl(host, port, timeout, now):
            return sp.SslCertInfo(
                days_remaining=42.5,
                not_after="2026-12-31T00:00:00Z",
                subject=f"CN={host}",
                issuer="CN=Test CA",
            )

        res = sp.probe_target(target, http_fetcher=fake_fetch, ssl_inspector=fake_ssl, now=self.FIXED_NOW)
        self.assertEqual(res.status, sp.STATUS_OK)
        self.assertEqual(res.samples_succeeded, 5)
        self.assertEqual(res.min_ms, 10.0)
        self.assertEqual(res.avg_ms, 40.0)
        self.assertEqual(res.p50_ms, 30.0)
        self.assertEqual(res.p95_ms, 88.0)
        self.assertEqual(res.max_ms, 100.0)
        self.assertTrue(res.keyword_matched)
        self.assertTrue(res.ssl_checked)
        self.assertEqual(res.ssl_days_remaining, 42.5)
        self.assertEqual(res.reasons, [])

    def test_probe_target_degraded_when_p95_exceeds_threshold(self) -> None:
        latencies = iter([10.0, 20.0, 90.0])
        target = sp.ProbeTarget(
            url="http://localhost:8080/health",
            samples=3,
            warn_p95_ms=50.0,
        )
        res = sp.probe_target(
            target,
            http_fetcher=lambda _t: sp.HttpResponse(status=200, body=b"ok", latency_ms=next(latencies)),
            now=self.FIXED_NOW,
        )
        self.assertEqual(res.status, sp.STATUS_DEGRADED)
        self.assertEqual(res.p95_ms, 83.0)
        self.assertTrue(any("exceeds 50.00ms" in r for r in res.reasons))

    def test_probe_target_degraded_on_partial_sample_failures(self) -> None:
        responses = iter([
            sp.HttpResponse(status=200, body=b"ok", latency_ms=12.0),
            sp.HttpResponse(status=None, body=b"", latency_ms=500.0, error="URLError: reset"),
            sp.HttpResponse(status=200, body=b"ok", latency_ms=18.0),
        ])
        target = sp.ProbeTarget(url="http://service.internal/ping", samples=3, warn_p95_ms=500.0)
        res = sp.probe_target(target, http_fetcher=lambda _t: next(responses), now=self.FIXED_NOW)
        self.assertEqual(res.status, sp.STATUS_DEGRADED)
        self.assertEqual(res.samples_succeeded, 2)
        self.assertEqual(res.http_codes, [200, 200])
        self.assertTrue(any("2/3 samples succeeded" in r for r in res.reasons))

    def test_probe_target_critical_on_unexpected_status_code(self) -> None:
        target = sp.ProbeTarget(url="http://service.internal/ping", samples=2, expected_status=(200, 204))
        res = sp.probe_target(
            target,
            http_fetcher=lambda _t: sp.HttpResponse(status=502, body=b"Bad Gateway", latency_ms=14.0),
            now=self.FIXED_NOW,
        )
        self.assertEqual(res.status, sp.STATUS_CRITICAL)
        self.assertEqual(res.samples_succeeded, 0)
        self.assertTrue(any("unexpected HTTP status 502" in r for r in res.reasons))

    def test_probe_target_keyword_case_sensitivity(self) -> None:
        target_strict = sp.ProbeTarget(
            url="http://service.internal/",
            samples=1,
            keyword="Healthy",
            case_sensitive=True,
        )
        res_fail = sp.probe_target(
            target_strict,
            http_fetcher=lambda _t: sp.HttpResponse(status=200, body=b"status: healthy", latency_ms=5.0),
        )
        self.assertEqual(res_fail.status, sp.STATUS_CRITICAL)
        self.assertFalse(res_fail.keyword_matched)

        target_ci = sp.ProbeTarget(
            url="http://service.internal/",
            samples=1,
            keyword="Healthy",
            case_sensitive=False,
        )
        res_pass = sp.probe_target(
            target_ci,
            http_fetcher=lambda _t: sp.HttpResponse(status=200, body=b"status: healthy", latency_ms=5.0),
        )
        self.assertEqual(res_pass.status, sp.STATUS_OK)
        self.assertTrue(res_pass.keyword_matched)

    def test_probe_target_ssl_warning_critical_and_expired(self) -> None:
        ok_http = lambda _t: sp.HttpResponse(status=200, body=b"ok", latency_ms=15.0)
        target = sp.ProbeTarget(
            url="https://api.example.com/",
            samples=1,
            ssl_warn_days=14,
            ssl_crit_days=3,
        )

        res_warn = sp.probe_target(
            target,
            http_fetcher=ok_http,
            ssl_inspector=lambda *_: sp.SslCertInfo(days_remaining=10.0, not_after="2026-11-29T12:00:00Z"),
        )
        self.assertEqual(res_warn.status, sp.STATUS_DEGRADED)

        res_crit = sp.probe_target(
            target,
            http_fetcher=ok_http,
            ssl_inspector=lambda *_: sp.SslCertInfo(days_remaining=2.5, not_after="2026-11-22T00:00:00Z"),
        )
        self.assertEqual(res_crit.status, sp.STATUS_CRITICAL)

        res_expired = sp.probe_target(
            target,
            http_fetcher=ok_http,
            ssl_inspector=lambda *_: sp.SslCertInfo(days_remaining=-1.0, not_after="2026-11-18T12:00:00Z"),
        )
        self.assertEqual(res_expired.status, sp.STATUS_CRITICAL)
        self.assertTrue(any("expired" in r for r in res_expired.reasons))

    def test_probe_target_skips_ssl_for_http_or_when_disabled(self) -> None:
        ssl_calls: list[str] = []

        def spy_ssl(host, port, timeout, now):
            ssl_calls.append(host)
            return sp.SslCertInfo(days_remaining=30.0, not_after="2026-12-19T12:00:00Z")

        ok_http = lambda _t: sp.HttpResponse(status=200, body=b"ok", latency_ms=5.0)

        res_http = sp.probe_target(
            sp.ProbeTarget(url="http://example.com/", samples=1),
            http_fetcher=ok_http,
            ssl_inspector=spy_ssl,
        )
        res_disabled = sp.probe_target(
            sp.ProbeTarget(url="https://example.com/", samples=1, check_ssl=False),
            http_fetcher=ok_http,
            ssl_inspector=spy_ssl,
        )
        self.assertEqual(ssl_calls, [])
        self.assertFalse(res_http.ssl_checked)
        self.assertFalse(res_disabled.ssl_checked)

    def test_probe_target_interval_calls_sleeper_between_samples(self) -> None:
        sleeps: list[float] = []
        target = sp.ProbeTarget(url="http://example.com/", samples=3, interval_ms=250.0)
        sp.probe_target(
            target,
            http_fetcher=lambda _t: sp.HttpResponse(status=200, body=b"ok", latency_ms=5.0),
            sleeper=lambda secs: sleeps.append(secs),
        )
        self.assertEqual(sleeps, [0.25, 0.25])

    def test_load_targets_from_json_object_and_list_and_example_file(self) -> None:
        example_path = Path(__file__).resolve().parent.parent / "targets.example.json"
        example_targets = sp.load_targets_from_json(example_path)
        self.assertEqual(len(example_targets), 3)
        self.assertEqual(example_targets[0].name, "Public API Health")
        self.assertEqual(example_targets[0].expected_status, (200, 204))
        self.assertEqual(example_targets[2].samples, 5)
        self.assertIs(example_targets[2].check_ssl, False)

        with tempfile.TemporaryDirectory() as tmpdir:
            list_file = Path(tmpdir) / "urls.json"
            list_file.write_text(
                json.dumps([
                    "https://one.example.com/health",
                    {"name": "Two", "url": "https://two.example.com/", "samples": 2},
                ]),
                encoding="utf-8",
            )
            loaded = sp.load_targets_from_json(list_file, base_defaults={"samples": 4})
            self.assertEqual(len(loaded), 2)
            self.assertEqual(loaded[0].samples, 4)
            self.assertEqual(loaded[1].name, "Two")
            self.assertEqual(loaded[1].samples, 2)

    def test_load_targets_from_json_invalid_cases(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            missing = Path(tmpdir) / "missing.json"
            with self.assertRaises(ValueError):
                sp.load_targets_from_json(missing)

            bad_json = Path(tmpdir) / "bad.json"
            bad_json.write_text("{not-json", encoding="utf-8")
            with self.assertRaises(ValueError):
                sp.load_targets_from_json(bad_json)

            empty_list = Path(tmpdir) / "empty.json"
            empty_list.write_text("[]", encoding="utf-8")
            with self.assertRaises(ValueError):
                sp.load_targets_from_json(empty_list)

    def test_run_probes_exit_code_precedence(self) -> None:
        def fetch(target):
            if "down" in target.url:
                return sp.HttpResponse(status=500, body=b"err", latency_ms=10.0)
            if "slow" in target.url:
                return sp.HttpResponse(status=200, body=b"ok", latency_ms=1500.0)
            return sp.HttpResponse(status=200, body=b"ok", latency_ms=20.0)

        rep_ok = sp.run_probes(
            [sp.ProbeTarget(url="http://ok.example.com", samples=1)],
            http_fetcher=fetch,
            now=self.FIXED_NOW,
        )
        self.assertEqual(rep_ok.exit_code, sp.EXIT_OK)

        rep_deg = sp.run_probes(
            [
                sp.ProbeTarget(url="http://ok.example.com", samples=1),
                sp.ProbeTarget(url="http://slow.example.com", samples=1, warn_p95_ms=500.0),
            ],
            http_fetcher=fetch,
            now=self.FIXED_NOW,
        )
        self.assertEqual(rep_deg.exit_code, sp.EXIT_DEGRADED)

        rep_crit = sp.run_probes(
            [
                sp.ProbeTarget(url="http://ok.example.com", samples=1),
                sp.ProbeTarget(url="http://slow.example.com", samples=1, warn_p95_ms=500.0),
                sp.ProbeTarget(url="http://down.example.com", samples=1),
            ],
            http_fetcher=fetch,
            now=self.FIXED_NOW,
        )
        self.assertEqual(rep_crit.exit_code, sp.EXIT_CRITICAL)
        self.assertEqual((rep_crit.ok, rep_crit.degraded, rep_crit.critical), (1, 1, 1))

    def test_cli_main_json_and_csv_and_text_outputs(self) -> None:
        fake_http = lambda _t: sp.HttpResponse(status=200, body=b"service ok", latency_ms=25.0)
        fake_ssl = lambda host, port, timeout, now: sp.SslCertInfo(
            days_remaining=60.0,
            not_after="2027-01-18T12:00:00Z",
            subject=f"CN={host}",
            issuer="CN=Test CA",
        )

        out_json = io.StringIO()
        code_json = sp.main(
            ["https://api.example.com/health", "--samples", "2", "--keyword", "ok", "--format", "json"],
            http_fetcher=fake_http,
            ssl_inspector=fake_ssl,
            now=self.FIXED_NOW,
            stdout=out_json,
        )
        self.assertEqual(code_json, sp.EXIT_OK)
        parsed = json.loads(out_json.getvalue())
        self.assertEqual(parsed["summary"]["ok"], 1)
        self.assertEqual(parsed["results"][0]["p50_ms"], 25.0)
        self.assertEqual(parsed["results"][0]["ssl_days_remaining"], 60.0)

        out_csv = io.StringIO()
        code_csv = sp.main(
            ["https://api.example.com/health", "--samples", "2", "--format", "csv"],
            http_fetcher=fake_http,
            ssl_inspector=fake_ssl,
            now=self.FIXED_NOW,
            stdout=out_csv,
        )
        self.assertEqual(code_csv, sp.EXIT_OK)
        rows = list(csv.DictReader(io.StringIO(out_csv.getvalue())))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["status"], "OK")
        self.assertEqual(rows[0]["p95_ms"], "25.00")

        out_text = io.StringIO()
        code_text = sp.main(
            ["https://api.example.com/health", "--samples", "1", "--format", "text"],
            http_fetcher=fake_http,
            ssl_inspector=fake_ssl,
            now=self.FIXED_NOW,
            stdout=out_text,
        )
        self.assertEqual(code_text, sp.EXIT_OK)
        self.assertIn("HTTP & SSL Probe Summary", out_text.getvalue())
        self.assertIn("60.0d", out_text.getvalue())

    def test_cli_main_output_file_and_missing_args_exit_2(self) -> None:
        err = io.StringIO()
        code_missing = sp.main([], stderr=err)
        self.assertEqual(code_missing, sp.EXIT_CRITICAL)
        self.assertIn("Provide at least one URL", err.getvalue())

        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = Path(tmpdir) / "probe_report.json"
            code = sp.main(
                ["http://localhost:8080/health", "-n", "1", "-f", "json", "-o", str(out_file)],
                http_fetcher=lambda _t: sp.HttpResponse(status=200, body=b"ok", latency_ms=11.0),
                now=self.FIXED_NOW,
            )
            self.assertEqual(code, sp.EXIT_OK)
            written = json.loads(out_file.read_text(encoding="utf-8"))
            self.assertEqual(written["exit_code"], 0)
            self.assertEqual(written["results"][0]["min_ms"], 11.0)


if __name__ == "__main__":
    unittest.main()

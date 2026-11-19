#!/usr/bin/env python3
"""Zero-dependency HTTP latency, keyword, and TLS/SSL certificate expiry probe CLI."""

from __future__ import annotations

import argparse
import csv
import io
import json
import math
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Union

STATUS_OK = "OK"
STATUS_DEGRADED = "DEGRADED"
STATUS_CRITICAL = "CRITICAL"

EXIT_OK = 0
EXIT_DEGRADED = 1
EXIT_CRITICAL = 2

_STATUS_RANK = {
    STATUS_OK: 0,
    STATUS_DEGRADED: 1,
    STATUS_CRITICAL: 2,
}

_X509_SHORT_NAMES = {
    "commonName": "CN",
    "organizationName": "O",
    "organizationalUnitName": "OU",
    "countryName": "C",
    "stateOrProvinceName": "ST",
    "localityName": "L",
}


@dataclass(frozen=True)
class ProbeTarget:
    """Configuration for a single HTTP/HTTPS probe target."""

    url: str
    name: str = ""
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    expected_status: Optional[Tuple[int, ...]] = None
    keyword: Optional[str] = None
    case_sensitive: bool = True
    samples: int = 3
    timeout: float = 5.0
    warn_p95_ms: float = 1000.0
    ssl_warn_days: int = 14
    ssl_crit_days: int = 3
    check_ssl: Optional[bool] = None
    follow_redirects: bool = True
    interval_ms: float = 0.0

    def __post_init__(self) -> None:
        if not self.name:
            object.__setattr__(self, "name", self.url)
        object.__setattr__(self, "method", self.method.upper().strip() or "GET")
        if self.samples < 1:
            raise ValueError(f"samples must be >= 1 for target {self.url!r}")
        if self.timeout <= 0:
            raise ValueError(f"timeout must be > 0 for target {self.url!r}")
        if self.warn_p95_ms < 0:
            raise ValueError(f"warn_p95_ms must be >= 0 for target {self.url!r}")
        if self.ssl_warn_days < 0 or self.ssl_crit_days < 0:
            raise ValueError(f"SSL day thresholds must be >= 0 for target {self.url!r}")
        if self.interval_ms < 0:
            raise ValueError(f"interval_ms must be >= 0 for target {self.url!r}")


@dataclass(frozen=True)
class HttpResponse:
    """Outcome of a single HTTP request attempt."""

    status: Optional[int]
    body: bytes
    latency_ms: float
    headers: Dict[str, str] = field(default_factory=dict)
    error: Optional[str] = None


@dataclass(frozen=True)
class SslCertInfo:
    """TLS/SSL peer certificate expiry details."""

    days_remaining: Optional[float]
    not_after: Optional[str]
    subject: str = ""
    issuer: str = ""
    error: Optional[str] = None


@dataclass(frozen=True)
class TargetProbeResult:
    """Aggregated probe metrics and health verdict for one target."""

    name: str
    url: str
    status: str
    samples_requested: int
    samples_succeeded: int
    http_codes: List[int]
    latencies_ms: List[float]
    min_ms: Optional[float]
    avg_ms: Optional[float]
    p50_ms: Optional[float]
    p95_ms: Optional[float]
    max_ms: Optional[float]
    keyword: Optional[str]
    keyword_matched: Optional[bool]
    ssl_checked: bool
    ssl_days_remaining: Optional[float]
    ssl_not_after: Optional[str]
    ssl_subject: str
    ssl_issuer: str
    ssl_error: Optional[str]
    reasons: List[str]


@dataclass(frozen=True)
class ProbeReport:
    """Full run report across all probed targets."""

    generated_at: str
    exit_code: int
    total: int
    ok: int
    degraded: int
    critical: int
    results: List[TargetProbeResult]


HttpFetcher = Callable[[ProbeTarget], HttpResponse]
SslInspector = Callable[[str, int, float, datetime], SslCertInfo]


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Redirect handler that surfaces 3xx responses instead of following them."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> Optional[urllib.request.Request]:
        return None


def compute_percentile(values: Sequence[float], pct: float) -> Optional[float]:
    """Compute a linear-interpolated percentile (0 <= pct <= 100) in milliseconds."""
    if not values:
        return None
    if pct < 0 or pct > 100:
        raise ValueError(f"Percentile must be between 0 and 100, got {pct}")
    ordered = sorted(float(v) for v in values)
    n = len(ordered)
    if n == 1:
        return round(ordered[0], 2)
    pos = (pct / 100.0) * (n - 1)
    lo = math.floor(pos)
    hi = math.ceil(pos)
    if lo == hi:
        return round(ordered[lo], 2)
    frac = pos - lo
    interpolated = ordered[lo] + frac * (ordered[hi] - ordered[lo])
    return round(interpolated, 2)


def parse_expected_status(raw: Any) -> Optional[Tuple[int, ...]]:
    """Parse expected HTTP status code(s) from int, CSV string, or sequence."""
    if raw is None:
        return None
    if isinstance(raw, bool):
        raise ValueError("expected_status cannot be a boolean")
    if isinstance(raw, int):
        codes = [raw]
    elif isinstance(raw, str):
        parts = [part.strip() for part in raw.split(",") if part.strip()]
        if not parts:
            return None
        try:
            codes = [int(part) for part in parts]
        except ValueError as exc:
            raise ValueError(f"Invalid HTTP status code in {raw!r}") from exc
    elif isinstance(raw, (list, tuple)):
        codes = []
        for item in raw:
            if isinstance(item, bool) or not isinstance(item, int):
                raise ValueError(f"Invalid HTTP status code entry: {item!r}")
            codes.append(item)
    else:
        raise ValueError(f"Unsupported expected_status type: {type(raw).__name__}")

    for code in codes:
        if code < 100 or code > 599:
            raise ValueError(f"HTTP status code out of range (100-599): {code}")
    return tuple(codes)


def validate_url(url: str) -> Tuple[str, str, int]:
    """Validate an HTTP/HTTPS URL and return (scheme, host, port)."""
    if not isinstance(url, str) or not url.strip():
        raise ValueError("URL must be a non-empty string")
    parsed = urllib.parse.urlsplit(url.strip())
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError(f"Unsupported URL scheme {parsed.scheme!r} in {url!r}; expected http or https")
    host = parsed.hostname
    if not host:
        raise ValueError(f"Missing hostname in URL {url!r}")
    port = parsed.port
    if port is None:
        port = 443 if scheme == "https" else 80
    return scheme, host, port


def _extract_x509_name(raw_name: Any) -> str:
    """Format an X.509 name tuple from ssl.getpeercert() into a readable string."""
    if not raw_name:
        return ""
    parts: List[str] = []
    for rdn in raw_name:
        if not isinstance(rdn, (tuple, list)):
            continue
        for attr in rdn:
            if isinstance(attr, (tuple, list)) and len(attr) == 2:
                key, value = str(attr[0]), str(attr[1])
                short_key = _X509_SHORT_NAMES.get(key, key)
                parts.append(f"{short_key}={value}")
    return ", ".join(parts)


def _parse_cert_expiry(not_after: str) -> datetime:
    """Parse an OpenSSL/ASN.1 certificate notAfter string into a UTC datetime."""
    if not not_after or not isinstance(not_after, str):
        raise ValueError("Missing notAfter certificate timestamp")
    try:
        ts = ssl.cert_time_to_seconds(not_after)
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    except Exception:
        cleaned = " ".join(not_after.split())
        for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y"):
            try:
                parsed = datetime.strptime(cleaned, fmt)
                return parsed.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
        raise ValueError(f"Unrecognized certificate notAfter format: {not_after!r}")


def inspect_ssl_certificate(
    host: str,
    port: int,
    timeout: float = 5.0,
    now: Optional[datetime] = None,
    socket_connector: Optional[Callable[..., Any]] = None,
    ssl_context_factory: Optional[Callable[[], Any]] = None,
) -> SslCertInfo:
    """Connect over TLS and calculate days remaining until peer certificate expiry."""
    now_dt = now or datetime.now(timezone.utc)
    if now_dt.tzinfo is None:
        now_dt = now_dt.replace(tzinfo=timezone.utc)

    connector = socket_connector or socket.create_connection
    ctx_factory = ssl_context_factory or ssl.create_default_context

    try:
        ctx = ctx_factory()
        with connector((host, port), timeout=timeout) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                cert = tls_sock.getpeercert()
        if not cert or "notAfter" not in cert:
            return SslCertInfo(
                days_remaining=None,
                not_after=None,
                error="Peer certificate missing notAfter field",
            )
        not_after = str(cert["notAfter"])
        expiry_dt = _parse_cert_expiry(not_after)
        days_remaining = round((expiry_dt - now_dt).total_seconds() / 86400.0, 2)
        subject = _extract_x509_name(cert.get("subject"))
        issuer = _extract_x509_name(cert.get("issuer"))
        return SslCertInfo(
            days_remaining=days_remaining,
            not_after=expiry_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
            subject=subject,
            issuer=issuer,
            error=None,
        )
    except (ssl.SSLError, socket.timeout, TimeoutError, OSError, ValueError) as exc:
        return SslCertInfo(
            days_remaining=None,
            not_after=None,
            error=f"{type(exc).__name__}: {exc}",
        )


def fetch_http_once(
    target: ProbeTarget,
    urlopen_fn: Optional[Callable[..., Any]] = None,
    timer: Callable[[], float] = time.perf_counter,
) -> HttpResponse:
    """Perform one HTTP/HTTPS request using stdlib urllib and measure latency in ms."""
    headers = {"User-Agent": "http-latency-ssl-expiry-probe-cli-lite/1.0"}
    headers.update(target.headers)
    req = urllib.request.Request(target.url, headers=headers, method=target.method)

    if urlopen_fn is None:
        if target.follow_redirects:
            opener_fn = lambda r, timeout: urllib.request.urlopen(r, timeout=timeout)
        else:
            opener = urllib.request.build_opener(_NoRedirectHandler())
            opener_fn = lambda r, timeout: opener.open(r, timeout=timeout)
    else:
        opener_fn = urlopen_fn

    start = timer()
    try:
        with opener_fn(req, timeout=target.timeout) as resp:
            raw_body = resp.read()
            elapsed_ms = round(max(0.0, (timer() - start) * 1000.0), 2)
            resp_headers = dict(resp.headers.items()) if getattr(resp, "headers", None) else {}
            status_code = int(getattr(resp, "status", resp.getcode()))
            return HttpResponse(
                status=status_code,
                body=raw_body if isinstance(raw_body, (bytes, bytearray)) else str(raw_body).encode("utf-8"),
                latency_ms=elapsed_ms,
                headers=resp_headers,
                error=None,
            )
    except urllib.error.HTTPError as exc:
        elapsed_ms = round(max(0.0, (timer() - start) * 1000.0), 2)
        try:
            raw_body = exc.read()
        except Exception:
            raw_body = b""
        resp_headers = dict(exc.headers.items()) if getattr(exc, "headers", None) else {}
        return HttpResponse(
            status=int(exc.code),
            body=raw_body if isinstance(raw_body, (bytes, bytearray)) else b"",
            latency_ms=elapsed_ms,
            headers=resp_headers,
            error=None,
        )
    except (urllib.error.URLError, TimeoutError, socket.timeout, OSError, ValueError) as exc:
        elapsed_ms = round(max(0.0, (timer() - start) * 1000.0), 2)
        reason = getattr(exc, "reason", exc)
        return HttpResponse(
            status=None,
            body=b"",
            latency_ms=elapsed_ms,
            headers={},
            error=f"{type(exc).__name__}: {reason}",
        )


def _escalate(current: str, candidate: str) -> str:
    return candidate if _STATUS_RANK[candidate] > _STATUS_RANK[current] else current


def _status_matches(code: Optional[int], expected: Optional[Tuple[int, ...]]) -> bool:
    if code is None:
        return False
    if expected is None:
        return 200 <= code < 300
    return code in expected


def _keyword_present(body: bytes, keyword: str, case_sensitive: bool) -> bool:
    text = body.decode("utf-8", errors="replace")
    if case_sensitive:
        return keyword in text
    return keyword.lower() in text.lower()


def probe_target(
    target: ProbeTarget,
    http_fetcher: Optional[HttpFetcher] = None,
    ssl_inspector: Optional[SslInspector] = None,
    now: Optional[datetime] = None,
    sleeper: Callable[[float], None] = time.sleep,
) -> TargetProbeResult:
    """Run N HTTP samples and optional TLS certificate expiry inspection for a target."""
    fetcher = http_fetcher or fetch_http_once
    inspector = ssl_inspector or inspect_ssl_certificate
    now_dt = now or datetime.now(timezone.utc)
    if now_dt.tzinfo is None:
        now_dt = now_dt.replace(tzinfo=timezone.utc)

    try:
        scheme, host, port = validate_url(target.url)
    except ValueError as exc:
        return TargetProbeResult(
            name=target.name,
            url=target.url,
            status=STATUS_CRITICAL,
            samples_requested=target.samples,
            samples_succeeded=0,
            http_codes=[],
            latencies_ms=[],
            min_ms=None,
            avg_ms=None,
            p50_ms=None,
            p95_ms=None,
            max_ms=None,
            keyword=target.keyword,
            keyword_matched=None,
            ssl_checked=False,
            ssl_days_remaining=None,
            ssl_not_after=None,
            ssl_subject="",
            ssl_issuer="",
            ssl_error=None,
            reasons=[f"Invalid URL: {exc}"],
        )

    http_codes: List[int] = []
    latencies_ms: List[float] = []
    sample_failures: List[str] = []
    samples_succeeded = 0
    keyword_hits = 0
    keyword_checks = 0

    for idx in range(target.samples):
        if idx > 0 and target.interval_ms > 0:
            sleeper(target.interval_ms / 1000.0)

        resp = fetcher(target)
        if resp.status is not None:
            http_codes.append(resp.status)
            latencies_ms.append(round(float(resp.latency_ms), 2))

        if resp.error:
            sample_failures.append(f"sample {idx + 1}: {resp.error}")
            continue

        if not _status_matches(resp.status, target.expected_status):
            expected_label = (
                ",".join(str(c) for c in target.expected_status)
                if target.expected_status
                else "2xx"
            )
            sample_failures.append(
                f"sample {idx + 1}: unexpected HTTP status {resp.status} (expected {expected_label})"
            )
            continue

        if target.keyword is not None:
            keyword_checks += 1
            if _keyword_present(resp.body, target.keyword, target.case_sensitive):
                keyword_hits += 1
            else:
                sample_failures.append(
                    f"sample {idx + 1}: keyword {target.keyword!r} not found"
                )
                continue

        samples_succeeded += 1

    min_ms = round(min(latencies_ms), 2) if latencies_ms else None
    max_ms = round(max(latencies_ms), 2) if latencies_ms else None
    avg_ms = round(sum(latencies_ms) / len(latencies_ms), 2) if latencies_ms else None
    p50_ms = compute_percentile(latencies_ms, 50.0)
    p95_ms = compute_percentile(latencies_ms, 95.0)

    keyword_matched: Optional[bool]
    if target.keyword is None:
        keyword_matched = None
    elif keyword_checks == 0:
        keyword_matched = False
    else:
        keyword_matched = keyword_hits == keyword_checks

    overall_status = STATUS_OK
    reasons: List[str] = []

    if samples_succeeded == 0:
        overall_status = _escalate(overall_status, STATUS_CRITICAL)
        if sample_failures:
            reasons.append(sample_failures[0])
            if len(sample_failures) > 1:
                reasons.append(f"{len(sample_failures)}/{target.samples} samples failed")
        else:
            reasons.append("All probe samples failed")
    elif samples_succeeded < target.samples:
        overall_status = _escalate(overall_status, STATUS_DEGRADED)
        reasons.append(
            f"Partial probe failure: {samples_succeeded}/{target.samples} samples succeeded ({sample_failures[0]})"
        )

    if target.warn_p95_ms > 0 and p95_ms is not None and p95_ms > target.warn_p95_ms:
        overall_status = _escalate(overall_status, STATUS_DEGRADED)
        reasons.append(f"p95 latency {p95_ms:.2f}ms exceeds {target.warn_p95_ms:.2f}ms threshold")

    should_check_ssl = target.check_ssl if target.check_ssl is not None else (scheme == "https")
    ssl_days_remaining: Optional[float] = None
    ssl_not_after: Optional[str] = None
    ssl_subject = ""
    ssl_issuer = ""
    ssl_error: Optional[str] = None

    if should_check_ssl and scheme == "https":
        cert = inspector(host, port, target.timeout, now_dt)
        ssl_days_remaining = cert.days_remaining
        ssl_not_after = cert.not_after
        ssl_subject = cert.subject
        ssl_issuer = cert.issuer
        ssl_error = cert.error

        if cert.error or cert.days_remaining is None:
            overall_status = _escalate(overall_status, STATUS_CRITICAL)
            reasons.append(f"SSL inspection failed: {cert.error or 'missing expiry'}")
        elif cert.days_remaining <= 0:
            overall_status = _escalate(overall_status, STATUS_CRITICAL)
            reasons.append(f"SSL certificate expired ({cert.days_remaining:.2f}d)")
        elif cert.days_remaining <= target.ssl_crit_days:
            overall_status = _escalate(overall_status, STATUS_CRITICAL)
            reasons.append(
                f"SSL certificate expires in {cert.days_remaining:.2f}d (<= {target.ssl_crit_days}d critical)"
            )
        elif cert.days_remaining <= target.ssl_warn_days:
            overall_status = _escalate(overall_status, STATUS_DEGRADED)
            reasons.append(
                f"SSL certificate expires in {cert.days_remaining:.2f}d (<= {target.ssl_warn_days}d warning)"
            )
    else:
        should_check_ssl = False

    return TargetProbeResult(
        name=target.name,
        url=target.url,
        status=overall_status,
        samples_requested=target.samples,
        samples_succeeded=samples_succeeded,
        http_codes=http_codes,
        latencies_ms=latencies_ms,
        min_ms=min_ms,
        avg_ms=avg_ms,
        p50_ms=p50_ms,
        p95_ms=p95_ms,
        max_ms=max_ms,
        keyword=target.keyword,
        keyword_matched=keyword_matched,
        ssl_checked=should_check_ssl,
        ssl_days_remaining=ssl_days_remaining,
        ssl_not_after=ssl_not_after,
        ssl_subject=ssl_subject,
        ssl_issuer=ssl_issuer,
        ssl_error=ssl_error,
        reasons=reasons,
    )


def run_probes(
    targets: Sequence[ProbeTarget],
    http_fetcher: Optional[HttpFetcher] = None,
    ssl_inspector: Optional[SslInspector] = None,
    now: Optional[datetime] = None,
    sleeper: Callable[[float], None] = time.sleep,
) -> ProbeReport:
    """Execute probes across all configured targets and compute the exit code."""
    now_dt = now or datetime.now(timezone.utc)
    if now_dt.tzinfo is None:
        now_dt = now_dt.replace(tzinfo=timezone.utc)

    results = [
        probe_target(
            target,
            http_fetcher=http_fetcher,
            ssl_inspector=ssl_inspector,
            now=now_dt,
            sleeper=sleeper,
        )
        for target in targets
    ]
    ok_count = sum(1 for r in results if r.status == STATUS_OK)
    degraded_count = sum(1 for r in results if r.status == STATUS_DEGRADED)
    critical_count = sum(1 for r in results if r.status == STATUS_CRITICAL)

    if critical_count > 0:
        exit_code = EXIT_CRITICAL
    elif degraded_count > 0:
        exit_code = EXIT_DEGRADED
    else:
        exit_code = EXIT_OK

    return ProbeReport(
        generated_at=now_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
        exit_code=exit_code,
        total=len(results),
        ok=ok_count,
        degraded=degraded_count,
        critical=critical_count,
        results=results,
    )


def load_targets_from_json(
    path: Union[str, Path],
    base_defaults: Optional[Dict[str, Any]] = None,
) -> List[ProbeTarget]:
    """Load probe targets from a JSON file (list of targets or {defaults, targets} object)."""
    target_path = Path(path)
    try:
        raw_text = target_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"Unable to read targets file {target_path}: {exc}") from exc

    try:
        payload = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in {target_path}: {exc}") from exc

    file_defaults: Dict[str, Any] = {}
    if isinstance(payload, list):
        raw_targets = payload
    elif isinstance(payload, dict):
        if "defaults" in payload:
            if not isinstance(payload["defaults"], dict):
                raise ValueError("'defaults' in targets JSON must be an object")
            file_defaults = dict(payload["defaults"])
        raw_targets = payload.get("targets")
        if not isinstance(raw_targets, list):
            raise ValueError("Targets JSON object must contain a 'targets' array")
    else:
        raise ValueError("Targets JSON must be an array or an object containing 'targets'")

    if not raw_targets:
        raise ValueError("Targets list cannot be empty")

    merged_defaults: Dict[str, Any] = dict(base_defaults or {})
    merged_defaults.update(file_defaults)

    targets: List[ProbeTarget] = []
    for idx, entry in enumerate(raw_targets):
        if isinstance(entry, str):
            cfg: Dict[str, Any] = dict(merged_defaults)
            cfg["url"] = entry
        elif isinstance(entry, dict):
            cfg = dict(merged_defaults)
            cfg.update(entry)
        else:
            raise ValueError(f"Target entry #{idx + 1} must be a URL string or object")

        if "url" not in cfg or not isinstance(cfg["url"], str):
            raise ValueError(f"Target entry #{idx + 1} is missing a valid 'url' string")

        headers_raw = cfg.get("headers") or {}
        if not isinstance(headers_raw, dict):
            raise ValueError(f"Target entry #{idx + 1} 'headers' must be an object")
        headers = {str(k): str(v) for k, v in headers_raw.items()}

        expected_status = parse_expected_status(cfg.get("expected_status"))
        check_ssl_raw = cfg.get("check_ssl")
        if check_ssl_raw is not None and not isinstance(check_ssl_raw, bool):
            raise ValueError(f"Target entry #{idx + 1} 'check_ssl' must be a boolean")

        targets.append(
            ProbeTarget(
                url=cfg["url"],
                name=str(cfg.get("name") or cfg["url"]),
                method=str(cfg.get("method", "GET")),
                headers=headers,
                expected_status=expected_status,
                keyword=cfg.get("keyword"),
                case_sensitive=bool(cfg.get("case_sensitive", True)),
                samples=int(cfg.get("samples", 3)),
                timeout=float(cfg.get("timeout", 5.0)),
                warn_p95_ms=float(cfg.get("warn_p95_ms", 1000.0)),
                ssl_warn_days=int(cfg.get("ssl_warn_days", 14)),
                ssl_crit_days=int(cfg.get("ssl_crit_days", 3)),
                check_ssl=check_ssl_raw,
                follow_redirects=bool(cfg.get("follow_redirects", True)),
                interval_ms=float(cfg.get("interval_ms", 0.0)),
            )
        )
    return targets


def _fmt_ms(val: Optional[float]) -> str:
    return f"{val:.2f}" if val is not None else "-"


def _fmt_ssl(result: TargetProbeResult) -> str:
    if not result.ssl_checked:
        return "-"
    if result.ssl_error:
        return "ERR"
    if result.ssl_days_remaining is None:
        return "-"
    return f"{result.ssl_days_remaining:.1f}d"


def _fmt_kw(result: TargetProbeResult) -> str:
    if result.keyword is None:
        return "-"
    return "PASS" if result.keyword_matched else "FAIL"


def format_text(report: ProbeReport) -> str:
    """Format ProbeReport as an aligned human-readable summary table."""
    lines: List[str] = [
        (
            f"HTTP & SSL Probe Summary | Generated: {report.generated_at} | "
            f"Total: {report.total} | OK: {report.ok} | Degraded: {report.degraded} | "
            f"Critical: {report.critical} | Exit: {report.exit_code}"
        ),
        "",
    ]
    headers = ["Status", "Target", "Codes", "OK/N", "p50(ms)", "p95(ms)", "Keyword", "SSL", "Notes"]
    rows: List[List[str]] = []
    for r in report.results:
        unique_codes = ",".join(str(c) for c in dict.fromkeys(r.http_codes)) if r.http_codes else "-"
        rows.append(
            [
                r.status,
                r.name,
                unique_codes,
                f"{r.samples_succeeded}/{r.samples_requested}",
                _fmt_ms(r.p50_ms),
                _fmt_ms(r.p95_ms),
                _fmt_kw(r),
                _fmt_ssl(r),
                "; ".join(r.reasons) if r.reasons else "healthy",
            ]
        )

    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))

    def render_row(cells: Sequence[str]) -> str:
        return " | ".join(cell.ljust(widths[i]) for i, cell in enumerate(cells))

    lines.append(render_row(headers))
    lines.append("-+-".join("-" * w for w in widths))
    for row in rows:
        lines.append(render_row(row))
    return "\n".join(lines)


def format_json(report: ProbeReport) -> str:
    """Format ProbeReport as structured indented JSON."""
    payload = {
        "generated_at": report.generated_at,
        "exit_code": report.exit_code,
        "summary": {
            "total": report.total,
            "ok": report.ok,
            "degraded": report.degraded,
            "critical": report.critical,
        },
        "results": [
            {
                "name": r.name,
                "url": r.url,
                "status": r.status,
                "samples_requested": r.samples_requested,
                "samples_succeeded": r.samples_succeeded,
                "http_codes": r.http_codes,
                "min_ms": r.min_ms,
                "avg_ms": r.avg_ms,
                "p50_ms": r.p50_ms,
                "p95_ms": r.p95_ms,
                "max_ms": r.max_ms,
                "keyword": r.keyword,
                "keyword_matched": r.keyword_matched,
                "ssl_checked": r.ssl_checked,
                "ssl_days_remaining": r.ssl_days_remaining,
                "ssl_not_after": r.ssl_not_after,
                "ssl_subject": r.ssl_subject,
                "ssl_issuer": r.ssl_issuer,
                "ssl_error": r.ssl_error,
                "reasons": r.reasons,
            }
            for r in report.results
        ],
    }
    return json.dumps(payload, indent=2)


def format_csv(report: ProbeReport) -> str:
    """Format ProbeReport as RFC 4180 CSV."""
    buf = io.StringIO(newline="")
    fieldnames = [
        "name",
        "url",
        "status",
        "samples_requested",
        "samples_succeeded",
        "http_codes",
        "min_ms",
        "avg_ms",
        "p50_ms",
        "p95_ms",
        "max_ms",
        "keyword_matched",
        "ssl_days_remaining",
        "ssl_not_after",
        "reasons",
    ]
    writer = csv.DictWriter(buf, fieldnames=fieldnames, lineterminator="\n")
    writer.writeheader()
    for r in report.results:
        writer.writerow(
            {
                "name": r.name,
                "url": r.url,
                "status": r.status,
                "samples_requested": r.samples_requested,
                "samples_succeeded": r.samples_succeeded,
                "http_codes": ";".join(str(c) for c in r.http_codes),
                "min_ms": "" if r.min_ms is None else f"{r.min_ms:.2f}",
                "avg_ms": "" if r.avg_ms is None else f"{r.avg_ms:.2f}",
                "p50_ms": "" if r.p50_ms is None else f"{r.p50_ms:.2f}",
                "p95_ms": "" if r.p95_ms is None else f"{r.p95_ms:.2f}",
                "max_ms": "" if r.max_ms is None else f"{r.max_ms:.2f}",
                "keyword_matched": "" if r.keyword_matched is None else str(r.keyword_matched).lower(),
                "ssl_days_remaining": "" if r.ssl_days_remaining is None else f"{r.ssl_days_remaining:.2f}",
                "ssl_not_after": r.ssl_not_after or "",
                "reasons": "; ".join(r.reasons),
            }
        )
    return buf.getvalue().rstrip("\n")


def build_parser() -> argparse.ArgumentParser:
    """Create the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="ssl_probe.py",
        description=(
            "Zero-dependency Python CLI to probe HTTP endpoints for status codes, "
            "p50/p95 latency, keyword presence, and TLS/SSL certificate days-to-expiry."
        ),
    )
    parser.add_argument(
        "urls",
        nargs="*",
        help="One or more HTTP/HTTPS URLs to probe directly",
    )
    parser.add_argument(
        "-t",
        "--targets",
        help="Path to a JSON file containing target URLs and per-target thresholds",
    )
    parser.add_argument(
        "-n",
        "--samples",
        type=int,
        default=3,
        help="Number of HTTP samples per target for p50/p95 latency (default: 3)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="HTTP and TLS socket timeout in seconds (default: 5.0)",
    )
    parser.add_argument(
        "--method",
        default="GET",
        help="HTTP method for CLI URLs (default: GET)",
    )
    parser.add_argument(
        "--expected-status",
        dest="expected_status",
        default=None,
        help="Comma-separated expected HTTP status code(s), e.g. 200,204 (default: any 2xx)",
    )
    parser.add_argument(
        "--keyword",
        default=None,
        help="Required substring in HTTP response body",
    )
    parser.add_argument(
        "--ignore-case",
        action="store_true",
        help="Perform case-insensitive keyword matching",
    )
    parser.add_argument(
        "--no-redirects",
        action="store_true",
        help="Do not automatically follow 3xx HTTP redirects",
    )
    parser.add_argument(
        "--warn-p95-ms",
        type=float,
        default=1000.0,
        help="Mark DEGRADED if p95 latency exceeds ms; 0 disables (default: 1000.0)",
    )
    parser.add_argument(
        "--ssl-warn-days",
        type=int,
        default=14,
        help="Mark DEGRADED if TLS certificate expires within N days (default: 14)",
    )
    parser.add_argument(
        "--ssl-crit-days",
        type=int,
        default=3,
        help="Mark CRITICAL if TLS certificate expires within N days (default: 3)",
    )
    parser.add_argument(
        "--skip-ssl",
        action="store_true",
        help="Skip TLS/SSL certificate expiry checks even for HTTPS targets",
    )
    parser.add_argument(
        "--interval-ms",
        type=float,
        default=0.0,
        help="Delay between samples in milliseconds (default: 0.0)",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["text", "json", "csv"],
        default="text",
        help="Output format: text, json, or csv (default: text)",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="Write formatted report to a UTF-8 file instead of stdout",
    )
    return parser


def main(
    argv: Optional[Sequence[str]] = None,
    *,
    http_fetcher: Optional[HttpFetcher] = None,
    ssl_inspector: Optional[SslInspector] = None,
    now: Optional[datetime] = None,
    sleeper: Callable[[float], None] = time.sleep,
    stdout: Optional[Any] = None,
    stderr: Optional[Any] = None,
) -> int:
    """CLI entrypoint returning process exit code (0 healthy, 1 degraded, 2 critical/error)."""
    out_stream = stdout or sys.stdout
    err_stream = stderr or sys.stderr
    parser = build_parser()

    try:
        args = parser.parse_args(list(argv) if argv is not None else None)
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else EXIT_CRITICAL

    if not args.urls and not args.targets:
        print("Error: Provide at least one URL or --targets <file.json>.", file=err_stream)
        return EXIT_CRITICAL

    try:
        expected_codes = parse_expected_status(args.expected_status)
        cli_defaults: Dict[str, Any] = {
            "method": args.method,
            "expected_status": expected_codes,
            "keyword": args.keyword,
            "case_sensitive": not args.ignore_case,
            "samples": args.samples,
            "timeout": args.timeout,
            "warn_p95_ms": args.warn_p95_ms,
            "ssl_warn_days": args.ssl_warn_days,
            "ssl_crit_days": args.ssl_crit_days,
            "check_ssl": False if args.skip_ssl else None,
            "follow_redirects": not args.no_redirects,
            "interval_ms": args.interval_ms,
        }

        targets: List[ProbeTarget] = []
        if args.targets:
            targets.extend(load_targets_from_json(args.targets, base_defaults=cli_defaults))

        for raw_url in args.urls:
            targets.append(
                ProbeTarget(
                    url=raw_url,
                    name=raw_url,
                    method=args.method,
                    expected_status=expected_codes,
                    keyword=args.keyword,
                    case_sensitive=not args.ignore_case,
                    samples=args.samples,
                    timeout=args.timeout,
                    warn_p95_ms=args.warn_p95_ms,
                    ssl_warn_days=args.ssl_warn_days,
                    ssl_crit_days=args.ssl_crit_days,
                    check_ssl=False if args.skip_ssl else None,
                    follow_redirects=not args.no_redirects,
                    interval_ms=args.interval_ms,
                )
            )
    except ValueError as exc:
        print(f"Configuration error: {exc}", file=err_stream)
        return EXIT_CRITICAL

    report = run_probes(
        targets,
        http_fetcher=http_fetcher,
        ssl_inspector=ssl_inspector,
        now=now,
        sleeper=sleeper,
    )

    if args.format == "json":
        rendered = format_json(report)
    elif args.format == "csv":
        rendered = format_csv(report)
    else:
        rendered = format_text(report)

    if args.output:
        try:
            Path(args.output).write_text(rendered + "\n", encoding="utf-8")
        except OSError as exc:
            print(f"Failed to write output file {args.output}: {exc}", file=err_stream)
            return EXIT_CRITICAL
    else:
        print(rendered, file=out_stream)

    return report.exit_code


if __name__ == "__main__":
    sys.exit(main())

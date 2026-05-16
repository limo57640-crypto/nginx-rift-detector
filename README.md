# nginx-rift-detector

**Free self-check script for CVE-2026-42945 (NGINX Rift) — the 18-year-old critical heap buffer overflow in `ngx_http_rewrite_module`.**

CVSS v4: **9.2 CRITICAL** | Unauthenticated | RCE when ASLR off | DoS on all configs | Public PoC available

## What It Does

| Check | What It Looks For |
|-------|-------------------|
| **Version** | Compares your NGINX version against fixed releases (1.30.1 / 1.31.0) |
| **Config Audit** | Scans `/etc/nginx/` for the dangerous rewrite pattern (unnamed captures + `?` + `set`/`if`) |
| **Access Logs** | Flags URIs > 2000 chars and heavy percent-encoding (exploitation indicators) |
| **Error Logs** | Detects worker crash loops (SIGABRT/SIGSEGV = heap corruption) |
| **ASLR** | Checks `/proc/sys/kernel/randomize_va_space` (0 = RCE trivial) |
| **Privileges** | Warns if NGINX workers run as root |

Output: **CLEAN**, **VULNERABLE**, or **SUSPICIOUS**.

## Quick Start

```bash
# One-liner (requires root for log access):
curl -sSL https://raw.githubusercontent.com/limo57640-crypto/nginx-rift-detector/main/detect.sh | sudo bash

# Or clone and run:
git clone https://github.com/limo57640-crypto/nginx-rift-detector.git
cd nginx-rift-detector
chmod +x detect.sh
sudo ./detect.sh
```

## The Vulnerability (TL;DR)

NGINX's rewrite engine has a two-pass process: first it calculates buffer size, then it copies data. The `is_args` flag is set on the main engine when a rewrite replacement contains `?`, but the length pass runs on a zeroed sub-engine where `is_args = 0`. This means:

1. **Length pass**: `is_args = 0` → returns raw capture length (too small)
2. **Copy pass**: `is_args = 1` → `ngx_escape_uri` expands escapable bytes to 3x

The copy overflows the heap buffer with attacker-controlled URI data.

**Trigger condition** (all must be true):
- NGINX version < 1.30.1
- `rewrite` directive with unnamed capture (`$1`, `$2`)
- Replacement string contains `?`
- Same block has `set`, `if`, or another `rewrite`

```nginx
# VULNERABLE:
rewrite ^/old/(.*)$ /new?path=$1 break;
set $original_path $1;

# SAFE (named capture):
rewrite ^/old/(?<mypath>.*)$ /new?path=$mypath break;
set $original_path $mypath;
```

## Affected Versions

| Product | Vulnerable | Fixed |
|---------|-----------|-------|
| NGINX Open Source | 0.6.27 – 1.30.0 | **1.30.1** / **1.31.0** |
| NGINX Plus | R32 – R36 | **R32 P6** / **R36 P4** |
| NGINX Ingress Controller | 3.5.0 – 5.4.1 | See [F5 advisory](https://my.f5.com/manage/s/article/K000161019) |
| NGINX Gateway Fabric | 1.3.0 – 2.5.1 | See F5 advisory |

## Related CVEs (Same Disclosure, May 13 2026)

| CVE | CVSS v4 | Module | Impact |
|-----|---------|--------|--------|
| **CVE-2026-42945** | 9.2 | rewrite | **Heap overflow → RCE** |
| CVE-2026-42946 | 8.3 | SCGI/uWSGI | Memory alloc → info leak/DoS |
| CVE-2026-40701 | 6.3 | SSL | UAF → DoS |
| CVE-2026-42934 | 6.3 | charset | OOB read → info leak |

All four are fixed by the same upgrade.

## References

- [NVD: CVE-2026-42945](https://nvd.nist.gov/vuln/detail/CVE-2026-42945)
- [F5 Advisory K000161019](https://my.f5.com/manage/s/article/K000161019)
- [depthfirst: NGINX Rift Research](https://depthfirst.com/research/nginx-rift-achieving-nginx-rce-via-an-18-year-old-vulnerability)
- [The Hacker News](https://thehackernews.com/2026/05/18-year-old-nginx-rewrite-module-flaw.html)
- [Full self-check guide on ping7.cc](https://ping7.cc/guides/nginx-rift-cve-2026-42945-self-check)

## Need Professional Help?

If the scanner shows **VULNERABLE** and you need hands-on assistance:

- **$49 Quick Patch** — 30-min screenshare, we patch + audit together
- **$199 Full NGINX Audit** — complete config review, TLS, rate limiting, all 4 CVEs

→ [ping7.cc/services](https://ping7.cc/services)

## License

MIT

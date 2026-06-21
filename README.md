# NGINX Rift Detector for CVE-2026-42945

Read-only Bash checker for owned NGINX servers. It helps an operator answer two questions after the CVE-2026-42945 disclosure:

- Is this server still running an exposed NGINX build or risky rewrite configuration?
- Do local logs show crash, long-URI, or encoding signals that need review before the ticket is closed?

[![CVE-2026-42945](https://img.shields.io/badge/CVE-2026--42945-critical-red)](https://nvd.nist.gov/vuln/detail/CVE-2026-42945)
[![CVSS 9.2](https://img.shields.io/badge/CVSS-9.2-critical-red)](https://nvd.nist.gov/vuln/detail/CVE-2026-42945)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Browse GitHub Page](https://img.shields.io/badge/Browse-GitHub%20Page-0969da)](https://limo57640-crypto.github.io/nginx-rift-detector/)
[![Ping7 Guide](https://img.shields.io/badge/Ping7-self--check-0f766e)](https://ping7.cc/guides/nginx-rift-cve-2026-42945-self-check/)
[![Ping7 Repair](https://img.shields.io/badge/Ping7-CVE%20repair-b91c1c)](https://ping7.cc/cve-repair/)

## Start Here

| Need | Link |
| --- | --- |
| Browse the tool page | https://limo57640-crypto.github.io/nginx-rift-detector/ |
| Read the Ping7 self-check guide | https://ping7.cc/guides/nginx-rift-cve-2026-42945-self-check/ |
| Compare with other Ping7 GitHub tools | https://ping7.cc/github-tools/ |
| Send suspicious output for repair | https://ping7.cc/cve-repair/ |

## Ping7 resources

- All GitHub tools: https://ping7.cc/github-tools/
- Full self-check guide: https://ping7.cc/guides/nginx-rift-cve-2026-42945-self-check/
- CVE repair service: https://ping7.cc/cve-repair/
- Sample repair report: https://ping7.cc/cve-repair/sample-report/
- Live CVE alerts: https://t.me/ping7cve

## Use This Repo When

- You operate NGINX directly, through a reverse proxy, or behind a hosting control panel.
- The server uses rewrite-heavy config and the patch window was not clearly documented.
- You need a terminal result that can be pasted into an incident ticket.
- You want a first pass before paying for cleanup or compromise review.

## Quick Start

Inspect first:

```bash
curl -fsSLO https://raw.githubusercontent.com/limo57640-crypto/nginx-rift-detector/main/detect.sh
less detect.sh
sudo bash detect.sh
```

Do not run remote shell content straight into root. Download the script, review
it, then run it on the server you are responsible for.

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

## Sample Output

```text
NGINX Rift CVE-2026-42945 Detector

Checks:
- NGINX version
- rewrite configuration
- access and error logs
- Linux ASLR
- worker user

Result: SUSPICIOUS (0 critical, 2 warnings)
Next: review rewrite rules and error-log crash entries before closing the ticket.
Guide: https://ping7.cc/guides/nginx-rift-cve-2026-42945-self-check
```

## Exit Status

This release is designed for interactive triage. It prints `CLEAN`, `VULNERABLE`,
or `SUSPICIOUS` in the terminal and normally exits `0` unless the shell runtime
itself fails. If you need CI-style exit codes, wrap the output status in your
own deployment pipeline.

## Limitations

- It cannot prove exploitation did or did not happen.
- It only reviews local files and logs available to the current user.
- Rotated, deleted, or off-host logs may hide the relevant window.
- Vendor backports can make a package version look older than the actual patched build.

## Fix Path

1. Upgrade NGINX to a fixed build from your vendor.
2. Replace unsafe rewrite capture patterns with safer named captures.
3. Keep ASLR enabled.
4. Review access and error logs from the exposure window.
5. Restart NGINX and confirm the detector reports clean.

## Repair Handoff

If the result is `VULNERABLE` or `SUSPICIOUS`, keep the output and send:

```text
Domain or server:
NGINX version:
CVE: CVE-2026-42945
Detector result: CLEAN / VULNERABLE / SUSPICIOUS
First suspicious timestamp:
Symptoms: worker crash, long URI logs, redirect, config change, or scanner result
Logs still available: yes / no
```

Do not send passwords in the first message. Send symptoms, timestamps, screenshots, and sanitized log snippets.

Need hands-on help: https://ping7.cc/cve-repair

## Contributing

Open an issue if you have a new defensive signal, a false positive, or a distro
version that is reported incorrectly. Include the NGINX version, OS family,
sanitized config line, and the detector result. Do not post live customer logs,
secrets, or attack strings.

## Defensive Scope

This project is defensive only. Run it only on systems you own or are authorized to audit.

It does not include offensive access code, credential theft, broad scanning, or abuse instructions.

## License

MIT

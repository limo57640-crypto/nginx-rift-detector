#!/usr/bin/env bash
# ============================================================================
# nginx-rift-detector  —  CVE-2026-42945 (NGINX Rift) Self-Check Script
# https://github.com/limo57640-crypto/nginx-rift-detector
#
# Checks:
#   1. NGINX version (vulnerable vs. patched)
#   2. Rewrite configuration audit (dangerous pattern detection)
#   3. Access log anomaly scan (long URIs, heavy percent-encoding)
#   4. Error log analysis (worker crash signals — SIGABRT, SIGSEGV)
#   5. ASLR status (code execution feasibility)
#   6. NGINX user privilege check
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/limo57640-crypto/nginx-rift-detector/main/detect.sh | sudo bash
#   # or
#   chmod +x detect.sh && sudo ./detect.sh
#
# Output: CLEAN / VULNERABLE / SUSPICIOUS
# License: MIT
# Author: ping7.cc
# ============================================================================

set -euo pipefail

# ----- colors -----
RED='\033[0;31m'
YEL='\033[1;33m'
GRN='\033[0;32m'
CYN='\033[0;36m'
BLD='\033[1m'
RST='\033[0m'

VULN_COUNT=0
WARN_COUNT=0

banner() {
  echo ""
  echo -e "${CYN}╔══════════════════════════════════════════════════════════════╗${RST}"
  echo -e "${CYN}║${RST}  ${BLD}nginx-rift-detector${RST}  —  CVE-2026-42945 Self-Check          ${CYN}║${RST}"
  echo -e "${CYN}║${RST}  https://ping7.cc/guides/nginx-rift-cve-2026-42945-self-check ${CYN}║${RST}"
  echo -e "${CYN}╚══════════════════════════════════════════════════════════════╝${RST}"
  echo ""
}

ok()   { echo -e "  [${GRN}  OK  ${RST}] $*"; }
warn() { echo -e "  [${YEL} WARN ${RST}] $*"; WARN_COUNT=$((WARN_COUNT + 1)); }
fail() { echo -e "  [${RED} VULN ${RST}] $*"; VULN_COUNT=$((VULN_COUNT + 1)); }
info() { echo -e "  [${CYN} INFO ${RST}] $*"; }

# ============================================================================
# 1. NGINX version check
# ============================================================================
check_version() {
  echo -e "\n${BLD}[1/6] NGINX Version Check${RST}"

  if ! command -v nginx &>/dev/null; then
    info "nginx binary not found in PATH. Skipping version check."
    info "If NGINX is installed in a non-standard location, run: /path/to/nginx -v"
    return
  fi

  local ver_line
  ver_line=$(nginx -v 2>&1 || true)
  local ver
  ver=$(echo "$ver_line" | grep -oP 'nginx/\K[0-9]+\.[0-9]+\.[0-9]+' || echo "")

  if [[ -z "$ver" ]]; then
    warn "Could not parse NGINX version from: $ver_line"
    return
  fi

  info "Detected NGINX version: ${BLD}$ver${RST}"

  # Compare against fixed versions: 1.30.1 (stable) and 1.31.0 (mainline)
  local major minor patch
  IFS='.' read -r major minor patch <<< "$ver"

  local is_fixed=0
  if (( major > 1 )); then
    is_fixed=1
  elif (( major == 1 )); then
    if (( minor > 31 )); then
      is_fixed=1
    elif (( minor == 31 )); then
      is_fixed=1  # 1.31.0+ is fixed
    elif (( minor == 30 && patch >= 1 )); then
      is_fixed=1  # 1.30.1 is the stable fix
    fi
  fi

  if (( is_fixed )); then
    ok "Version $ver is patched (>= 1.30.1 / 1.31.0)."
  else
    fail "Version $ver is VULNERABLE (< 1.30.1). Upgrade immediately!"
    fail "Fix: apt update && apt install --only-upgrade nginx  (or dnf update nginx)"
  fi
}

# ============================================================================
# 2. Rewrite configuration audit
# ============================================================================
check_rewrite_config() {
  echo -e "\n${BLD}[2/6] Rewrite Configuration Audit${RST}"

  local conf_dir="/etc/nginx"
  if [[ ! -d "$conf_dir" ]]; then
    # Try common alternative paths
    for alt in /usr/local/nginx/conf /usr/local/etc/nginx /opt/nginx/conf; do
      if [[ -d "$alt" ]]; then
        conf_dir="$alt"
        break
      fi
    done
  fi

  if [[ ! -d "$conf_dir" ]]; then
    warn "Cannot find NGINX config directory. Checked /etc/nginx and common alternatives."
    return
  fi

  info "Scanning config directory: $conf_dir"

  # The dangerous pattern: rewrite with unnamed capture ($1, $2, etc.)
  # and a ? in the replacement, followed by set/if/rewrite in the same scope.
  local hits
  hits=$(grep -rnP 'rewrite\s+\S+\s+\S*\?\S*\$[0-9]' "$conf_dir" 2>/dev/null || true)

  if [[ -z "$hits" ]]; then
    # Also check the reverse: $N before ?
    hits=$(grep -rnP 'rewrite\s+\S+\s+\S*\$[0-9]\S*\?' "$conf_dir" 2>/dev/null || true)
  fi

  if [[ -n "$hits" ]]; then
    fail "Found rewrite directives with unnamed captures AND question marks:"
    echo "$hits" | while IFS= read -r line; do
      echo -e "       ${RED}$line${RST}"
    done
    echo ""
    info "Check if these blocks also contain 'set', 'if', or another 'rewrite'."
    info "If yes, the vulnerability IS triggerable on your server."

    # Further check: look for set/if near the hits
    local hit_files
    hit_files=$(echo "$hits" | cut -d: -f1 | sort -u)
    for f in $hit_files; do
      local has_set
      has_set=$(grep -cP '^\s*(set|if)\s' "$f" 2>/dev/null || echo "0")
      if (( has_set > 0 )); then
        fail "File $f also contains 'set' or 'if' directives — EXPLOITABLE configuration!"
      fi
    done
  else
    ok "No dangerous rewrite patterns found in $conf_dir."
    info "The vulnerability requires: rewrite + unnamed capture + ? + set/if/rewrite."
  fi
}

# ============================================================================
# 3. Access log anomaly scan
# ============================================================================
check_access_logs() {
  echo -e "\n${BLD}[3/6] Access Log Anomaly Scan${RST}"

  local log_paths=()
  for p in /var/log/nginx/access.log /var/log/nginx/access.log.1 \
           /usr/local/nginx/logs/access.log /var/log/access.log; do
    [[ -f "$p" ]] && log_paths+=("$p")
  done

  if (( ${#log_paths[@]} == 0 )); then
    warn "No access log files found. Skipping anomaly scan."
    return
  fi

  for logfile in "${log_paths[@]}"; do
    info "Scanning: $logfile"

    # Long URIs (> 2000 chars in the request field)
    local long_uris
    long_uris=$(awk 'length($7) > 2000 {count++} END {print count+0}' "$logfile" 2>/dev/null || echo "0")
    if (( long_uris > 0 )); then
      warn "Found $long_uris requests with URI > 2000 chars (potential overflow attempts)."
    else
      ok "No abnormally long URIs detected."
    fi

    # Heavy percent-encoding (3+ encoded sequences in URI)
    local encoded
    encoded=$(grep -cP '%[0-9a-fA-F]{2}.*%[0-9a-fA-F]{2}.*%[0-9a-fA-F]{2}' "$logfile" 2>/dev/null || echo "0")
    if (( encoded > 50 )); then
      warn "Found $encoded requests with heavy percent-encoding (above baseline)."
    else
      ok "Percent-encoding levels look normal ($encoded requests)."
    fi
  done
}

# ============================================================================
# 4. Error log analysis (worker crash signals)
# ============================================================================
check_error_logs() {
  echo -e "\n${BLD}[4/6] Error Log Analysis (Worker Crashes)${RST}"

  local log_paths=()
  for p in /var/log/nginx/error.log /var/log/nginx/error.log.1 \
           /usr/local/nginx/logs/error.log /var/log/error.log; do
    [[ -f "$p" ]] && log_paths+=("$p")
  done

  if (( ${#log_paths[@]} == 0 )); then
    warn "No error log files found. Skipping crash analysis."
    return
  fi

  for logfile in "${log_paths[@]}"; do
    info "Scanning: $logfile"

    local crashes
    crashes=$(grep -ciP 'worker process.*((signal|exit).*(6|11|abort|segv|segfault))' "$logfile" 2>/dev/null || echo "0")

    if (( crashes > 10 )); then
      fail "Found $crashes worker crash events — possible active exploitation!"
      echo ""
      info "Last 5 crash entries:"
      grep -iP 'worker process.*((signal|exit).*(6|11|abort|segv|segfault))' "$logfile" 2>/dev/null | tail -5 | while IFS= read -r line; do
        echo -e "       ${RED}$line${RST}"
      done
    elif (( crashes > 0 )); then
      warn "Found $crashes worker crash events. Investigate if recent."
    else
      ok "No worker crash signals detected."
    fi
  done
}

# ============================================================================
# 5. ASLR status
# ============================================================================
check_aslr() {
  echo -e "\n${BLD}[5/6] ASLR Status${RST}"

  local aslr_file="/proc/sys/kernel/randomize_va_space"
  if [[ ! -f "$aslr_file" ]]; then
    info "Cannot check ASLR (not Linux or /proc not mounted)."
    return
  fi

  local aslr_val
  aslr_val=$(cat "$aslr_file" 2>/dev/null || echo "unknown")

  case "$aslr_val" in
    0)
      fail "ASLR is DISABLED (randomize_va_space = 0). RCE exploitation is trivial!"
      fail "Fix: echo 2 > /proc/sys/kernel/randomize_va_space"
      ;;
    1)
      warn "ASLR is partial (randomize_va_space = 1). Heap is not fully randomized."
      info "Recommended: echo 2 > /proc/sys/kernel/randomize_va_space"
      ;;
    2)
      ok "ASLR is fully enabled (randomize_va_space = 2). RCE is harder but DoS still possible."
      ;;
    *)
      warn "Could not determine ASLR status (value: $aslr_val)."
      ;;
  esac
}

# ============================================================================
# 6. NGINX user privilege check
# ============================================================================
check_nginx_user() {
  echo -e "\n${BLD}[6/6] NGINX Worker Privilege Check${RST}"

  local nginx_user
  nginx_user=$(ps -eo user,comm 2>/dev/null | grep '[n]ginx.*worker' | awk '{print $1}' | head -1)

  if [[ -z "$nginx_user" ]]; then
    nginx_user=$(grep -oP '^\s*user\s+\K\S+' /etc/nginx/nginx.conf 2>/dev/null | tr -d ';' || echo "")
  fi

  if [[ -z "$nginx_user" ]]; then
    info "Could not determine NGINX worker user (NGINX may not be running)."
    return
  fi

  info "NGINX worker runs as: ${BLD}$nginx_user${RST}"

  if [[ "$nginx_user" == "root" ]]; then
    fail "NGINX workers are running as ROOT! Any RCE = full system compromise."
    fail "Fix: Set 'user www-data;' (or 'user nginx;') in nginx.conf."
  else
    ok "Workers run as unprivileged user '$nginx_user'."
  fi
}

# ============================================================================
# Summary
# ============================================================================
summary() {
  echo ""
  echo -e "${BLD}═══════════════════════════════════════════════════════════════${RST}"

  if (( VULN_COUNT > 0 )); then
    echo -e "  Result:  ${RED}${BLD}VULNERABLE${RST}  ($VULN_COUNT critical findings, $WARN_COUNT warnings)"
    echo ""
    echo -e "  ${RED}Action required: Patch NGINX to 1.30.1+ and restart immediately.${RST}"
    echo -e "  Workaround: Replace unnamed captures (\$1) with named captures (\$path)."
  elif (( WARN_COUNT > 0 )); then
    echo -e "  Result:  ${YEL}${BLD}SUSPICIOUS${RST}  (0 critical, $WARN_COUNT warnings)"
    echo ""
    echo -e "  ${YEL}Review warnings above. Patch NGINX as a precaution.${RST}"
  else
    echo -e "  Result:  ${GRN}${BLD}CLEAN${RST}  (0 critical, 0 warnings)"
    echo ""
    echo -e "  ${GRN}No indicators of CVE-2026-42945 vulnerability or exploitation found.${RST}"
  fi

  echo ""
  echo -e "  Guide:   https://ping7.cc/guides/nginx-rift-cve-2026-42945-self-check"
  echo -e "  Source:   https://github.com/limo57640-crypto/nginx-rift-detector"
  echo -e "  Need help? https://ping7.cc/services"
  echo -e "${BLD}═══════════════════════════════════════════════════════════════${RST}"
  echo ""
}

# ============================================================================
# Main
# ============================================================================
main() {
  banner
  check_version
  check_rewrite_config
  check_access_logs
  check_error_logs
  check_aslr
  check_nginx_user
  summary
}

main "$@"

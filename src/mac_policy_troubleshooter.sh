#!/usr/bin/env bash
set -u

SERVICE=""
TARGET_PATH=""
HOURS=24
OUTPUT_DIR=""

usage() {
  echo "Usage: mac_policy_troubleshooter.sh [--service NAME] [--path PATH] [--hours N] [--output DIR]"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --service) SERVICE="${2:-}"; shift 2 ;;
    --path) TARGET_PATH="${2:-}"; shift 2 ;;
    --hours) HOURS="${2:-24}"; shift 2 ;;
    --output) OUTPUT_DIR="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

[[ "$HOURS" =~ ^[0-9]+$ ]] || { echo "--hours must be numeric" >&2; exit 2; }

STAMP="$(date +%Y%m%d_%H%M%S)"
OUTPUT_DIR="${OUTPUT_DIR:-./mac-policy-troubleshooting-$STAMP}"
mkdir -p "$OUTPUT_DIR"
REPORT="$OUTPUT_DIR/mac-policy-report.txt"
CSV="$OUTPUT_DIR/denial-events.csv"
JSON="$OUTPUT_DIR/summary.json"
ERRORS="$OUTPUT_DIR/command-errors.log"
SELINUX_RAW="$OUTPUT_DIR/selinux-denials.log"
APPARMOR_RAW="$OUTPUT_DIR/apparmor-denials.log"
: > "$REPORT"
: > "$ERRORS"
: > "$SELINUX_RAW"
: > "$APPARMOR_RAW"
echo 'framework,message' > "$CSV"

section() {
  local title="$1"
  shift
  {
    printf '\n===== %s =====\n' "$title"
    "$@"
  } >> "$REPORT" 2>> "$ERRORS" || true
}

have() { command -v "$1" >/dev/null 2>&1; }

csv_message() {
  local framework="$1"
  local message="$2"
  message="${message//\"/\"\"}"
  printf '"%s","%s"\n' "$framework" "$message" >> "$CSV"
}

section "Collection metadata" bash -c 'date -Is; hostname -f 2>/dev/null || hostname; cat /etc/os-release 2>/dev/null || true; id'
section "Security filesystem" bash -c 'mount | grep -E "securityfs|selinuxfs" || true; ls -ld /sys/fs/selinux /sys/kernel/security/apparmor 2>/dev/null || true'
section "Audit service" bash -c 'systemctl status auditd --no-pager -l 2>/dev/null || true; systemctl is-enabled auditd 2>/dev/null || true'
section "Process security labels" bash -c 'ps -eZ 2>/dev/null | head -n 300 || ps aux | head -n 100'

SELINUX_PRESENT=false
SELINUX_MODE="not-detected"
SELINUX_POLICY="unknown"
SELINUX_DENIALS=0

if [[ -d /sys/fs/selinux ]] || have getenforce || have sestatus; then
  SELINUX_PRESENT=true

  if have getenforce; then
    SELINUX_MODE="$(getenforce 2>>"$ERRORS" || echo unknown)"
  fi

  if have sestatus; then
    section "SELinux status" sestatus
    SELINUX_POLICY="$(sestatus 2>/dev/null | awk -F: '/Loaded policy name/ {gsub(/^[[:space:]]+/,"",$2); print $2; exit}')"
  fi

  if have getsebool; then
    section "SELinux booleans" getsebool -a
  fi

  if have semanage; then
    section "SELinux policy modules" semanage module -l
    section "SELinux port contexts" semanage port -l
  fi

  if have ausearch; then
    ausearch -m AVC,USER_AVC -ts recent -i > "$SELINUX_RAW" 2>> "$ERRORS" || true
  fi

  if [[ ! -s "$SELINUX_RAW" ]] && have journalctl; then
    journalctl --since "$HOURS hours ago" --no-pager 2>/dev/null | grep -Ei 'avc:.*denied|type=AVC|type=USER_AVC|selinux.*denied' > "$SELINUX_RAW" || true
  fi

  section "Recent SELinux denials" cat "$SELINUX_RAW"

  if have audit2why && [[ -s "$SELINUX_RAW" ]]; then
    section "SELinux denial interpretation" audit2why -i "$SELINUX_RAW"
  fi

  while IFS= read -r line; do
    [[ -n "$line" ]] && csv_message "SELinux" "$line"
  done < "$SELINUX_RAW"

  SELINUX_DENIALS="$(grep -Eic 'denied|type=AVC|type=USER_AVC' "$SELINUX_RAW" 2>/dev/null || true)"
fi

APPARMOR_PRESENT=false
APPARMOR_MODE="not-detected"
APPARMOR_DENIALS=0
APPARMOR_ENFORCING=0
APPARMOR_COMPLAIN=0

if [[ -d /sys/kernel/security/apparmor ]] || have aa-status || have apparmor_status; then
  APPARMOR_PRESENT=true

  if have aa-status; then
    section "AppArmor status" aa-status
    APPARMOR_MODE="loaded"
    APPARMOR_ENFORCING="$(aa-status 2>/dev/null | awk '/profiles are in enforce mode/ {print $1; exit}')"
    APPARMOR_COMPLAIN="$(aa-status 2>/dev/null | awk '/profiles are in complain mode/ {print $1; exit}')"
  elif have apparmor_status; then
    section "AppArmor status" apparmor_status
    APPARMOR_MODE="loaded"
  fi

  section "AppArmor loaded profiles" bash -c 'cat /sys/kernel/security/apparmor/profiles 2>/dev/null || true'

  if have journalctl; then
    journalctl --since "$HOURS hours ago" --no-pager 2>/dev/null | grep -Ei 'apparmor=.*DENIED|apparmor="DENIED"|audit.*apparmor' > "$APPARMOR_RAW" || true
  elif [[ -r /var/log/audit/audit.log ]]; then
    grep -Ei 'apparmor=.*DENIED|apparmor="DENIED"' /var/log/audit/audit.log | tail -n 1000 > "$APPARMOR_RAW" || true
  fi

  section "Recent AppArmor denials" cat "$APPARMOR_RAW"

  while IFS= read -r line; do
    [[ -n "$line" ]] && csv_message "AppArmor" "$line"
  done < "$APPARMOR_RAW"

  APPARMOR_DENIALS="$(grep -Eic 'DENIED' "$APPARMOR_RAW" 2>/dev/null || true)"
fi

if [[ -n "$SERVICE" ]]; then
  section "Target service status" systemctl status "$SERVICE" --no-pager -l
  section "Target service journal" journalctl -u "$SERVICE" --since "$HOURS hours ago" --no-pager -n 1000
  section "Target service process labels" bash -c "ps -eZ 2>/dev/null | grep -i -- '$SERVICE' || ps aux | grep -i -- '$SERVICE' | grep -v grep || true"
fi

if [[ -n "$TARGET_PATH" ]]; then
  if [[ -e "$TARGET_PATH" ]]; then
    section "Target path metadata" ls -ldZ "$TARGET_PATH"
    if have matchpathcon; then
      section "Expected SELinux path context" matchpathcon -V "$TARGET_PATH"
    fi
    if have namei; then
      section "Target path component permissions" namei -l "$TARGET_PATH"
    fi
  else
    printf '\n===== Target path =====\nPath does not exist: %s\n' "$TARGET_PATH" >> "$REPORT"
  fi
fi

TOTAL_DENIALS=$((SELINUX_DENIALS + APPARMOR_DENIALS))
OVERALL="No recent denials detected"
[[ "$TOTAL_DENIALS" -gt 0 ]] && OVERALL="Denials require review"

cat > "$JSON" <<EOF
{
  "collected_at": "$(date -Is)",
  "hostname": "$(hostname -f 2>/dev/null || hostname)",
  "selinux_present": $SELINUX_PRESENT,
  "selinux_mode": "$SELINUX_MODE",
  "selinux_policy": "${SELINUX_POLICY:-unknown}",
  "selinux_denial_entries": ${SELINUX_DENIALS:-0},
  "apparmor_present": $APPARMOR_PRESENT,
  "apparmor_state": "$APPARMOR_MODE",
  "apparmor_enforcing_profiles": ${APPARMOR_ENFORCING:-0},
  "apparmor_complain_profiles": ${APPARMOR_COMPLAIN:-0},
  "apparmor_denial_entries": ${APPARMOR_DENIALS:-0},
  "target_service": "$SERVICE",
  "target_path": "$TARGET_PATH",
  "overall_status": "$OVERALL"
}
EOF

printf '\nSELinux and AppArmor troubleshooting completed: %s\n' "$OUTPUT_DIR" | tee -a "$REPORT"

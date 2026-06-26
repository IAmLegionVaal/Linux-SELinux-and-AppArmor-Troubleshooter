#!/usr/bin/env bash
set -u

RESTORE_PATH=""
APPARMOR_PROFILE=""
APPARMOR_FILE=""
RESTART_AUDIT=false
DRY_RUN=false
ASSUME_YES=false
OUTPUT_DIR=""
FAILURES=0
ACTIONS=0

usage() {
  cat <<'EOF'
Usage: mac_policy_repair.sh [options]

  --restorecon PATH            Restore default SELinux labels below PATH.
  --apparmor-enforce PROFILE   Place one loaded AppArmor profile in enforce mode.
  --reload-apparmor FILE       Validate and reload one profile below /etc/apparmor.d.
  --restart-audit              Restart the installed audit service.
  --dry-run                    Show commands without changing policy state.
  --yes                        Skip confirmation prompts.
  --output DIR                 Save logs and before/after evidence in DIR.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --restorecon) RESTORE_PATH="${2:-}"; shift 2 ;;
    --apparmor-enforce) APPARMOR_PROFILE="${2:-}"; shift 2 ;;
    --reload-apparmor) APPARMOR_FILE="${2:-}"; shift 2 ;;
    --restart-audit) RESTART_AUDIT=true; shift ;;
    --dry-run) DRY_RUN=true; shift ;;
    --yes) ASSUME_YES=true; shift ;;
    --output) OUTPUT_DIR="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

if [ -z "$RESTORE_PATH" ] && [ -z "$APPARMOR_PROFILE" ] && [ -z "$APPARMOR_FILE" ] && ! $RESTART_AUDIT; then echo "Choose at least one repair action." >&2; exit 2; fi
if [ -n "$RESTORE_PATH" ]; then [ -e "$RESTORE_PATH" ] || { echo "Path not found: $RESTORE_PATH" >&2; exit 2; }; fi
if [ -n "$APPARMOR_FILE" ]; then
  [ -f "$APPARMOR_FILE" ] || { echo "AppArmor profile file not found." >&2; exit 2; }
  case "$APPARMOR_FILE" in /etc/apparmor.d/*) : ;; *) echo "Profile file must be below /etc/apparmor.d." >&2; exit 2 ;; esac
fi

STAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="${OUTPUT_DIR:-./mac-policy-repair-$STAMP}"
mkdir -p "$OUTPUT_DIR"
LOG="$OUTPUT_DIR/repair.log"
BEFORE="$OUTPUT_DIR/before.txt"
AFTER="$OUTPUT_DIR/after.txt"
: > "$LOG"

log() { printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" | tee -a "$LOG"; }
confirm() { $ASSUME_YES && return 0; read -r -p "$1 [y/N]: " answer; case "$answer" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac; }
run_action() {
  local description="$1"; shift
  ACTIONS=$((ACTIONS + 1)); log "$description"
  if $DRY_RUN; then
    {
      printf 'DRY-RUN:'
      printf ' %q' "$@"
      printf '\n'
    } >> "$LOG"
    return 0
  fi
  if "$@" >> "$LOG" 2>&1; then log "SUCCESS: $description"; return 0; fi
  FAILURES=$((FAILURES + 1)); log "WARNING: $description failed"; return 1
}
run_root() { local description="$1"; shift; if [ "$(id -u)" -eq 0 ]; then run_action "$description" "$@"; else run_action "$description" sudo "$@"; fi; }
collect_state() {
  local destination="$1"
  {
    echo "Collected: $(date -Is)"
    if command -v getenforce >/dev/null 2>&1; then getenforce || true; fi
    if command -v sestatus >/dev/null 2>&1; then sestatus || true; fi
    echo
    if command -v aa-status >/dev/null 2>&1; then aa-status || true; fi
    echo
    systemctl status auditd --no-pager -l 2>/dev/null || true
    echo
    journalctl -n 150 --no-pager 2>/dev/null | grep -Ei 'avc:|apparmor=.*denied|selinux' || true
  } > "$destination"
}

collect_state "$BEFORE"
confirm "Apply the selected SELinux or AppArmor repairs?" || { log "Repair cancelled."; exit 10; }

if [ -n "$RESTORE_PATH" ]; then
  if command -v restorecon >/dev/null 2>&1; then run_root "Restoring SELinux labels below $RESTORE_PATH" restorecon -Rv "$RESTORE_PATH" || true; else FAILURES=$((FAILURES + 1)); log "WARNING: restorecon is not installed."; fi
fi

if [ -n "$APPARMOR_PROFILE" ]; then
  if command -v aa-enforce >/dev/null 2>&1; then run_root "Placing AppArmor profile $APPARMOR_PROFILE in enforce mode" aa-enforce "$APPARMOR_PROFILE" || true; else FAILURES=$((FAILURES + 1)); log "WARNING: aa-enforce is not installed."; fi
fi

if [ -n "$APPARMOR_FILE" ]; then
  if command -v apparmor_parser >/dev/null 2>&1; then
    run_root "Validating AppArmor profile $APPARMOR_FILE" apparmor_parser -Q "$APPARMOR_FILE" || true
    [ "$FAILURES" -gt 0 ] || run_root "Reloading AppArmor profile $APPARMOR_FILE" apparmor_parser -r "$APPARMOR_FILE" || true
  else
    FAILURES=$((FAILURES + 1)); log "WARNING: apparmor_parser is not installed."
  fi
fi

if $RESTART_AUDIT; then
  if systemctl list-unit-files auditd.service >/dev/null 2>&1; then run_root "Restarting auditd" systemctl restart auditd || true
  elif systemctl list-unit-files apparmor.service >/dev/null 2>&1; then run_root "Restarting AppArmor service" systemctl restart apparmor || true
  else FAILURES=$((FAILURES + 1)); log "WARNING: audit or AppArmor service was not found."; fi
fi

$DRY_RUN || sleep 2
collect_state "$AFTER"
if [ "$FAILURES" -gt 0 ]; then exit 20; fi
log "Policy repair completed successfully. Actions performed: $ACTIONS"
exit 0

#!/bin/bash
set -eu

ScriptName="Collect-Running-Processes"
LogPath="/tmp/${ScriptName}-script.log"
ARLog="/var/ossec/logs/active-responses.log"
LogMaxKB=100
LogKeep=5
HostName="$(hostname)"
runStart="$(date +%s)"

WriteLog() {
  msg="$1"; level="${2:-INFO}"
  ts="$(date '+%Y-%m-%d %H:%M:%S')"
  line="[$ts][$level] $msg"
  printf '%s\n' "$line" >&2
  printf '%s\n' "$line" >> "$LogPath"
}

RotateLog() {
  [ -f "$LogPath" ] || return 0
  size_kb=$(du -k "$LogPath" | awk '{print $1}')
  [ "$size_kb" -le "$LogMaxKB" ] && return 0
  i=$((LogKeep-1))
  while [ $i -ge 0 ]; do
    [ -f "$LogPath.$i" ] && mv -f "$LogPath.$i" "$LogPath.$((i+1))"
    i=$((i-1))
  done
  mv -f "$LogPath" "$LogPath.1"
}

iso_now() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
escape_json() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'; }

BeginNDJSON() { TMP_AR="$(mktemp)"; }
AddRecord() {
  ts="$(iso_now)"
  pid_num="$1"; ppid_num="$2"; user="$3"; cmd="$4"; exe="$5"; sha256="$6"; kernel="$7"
  if [ -z "${pid_num:-}" ]; then return; fi
  if [ -z "${ppid_num:-}" ]; then ppid_num=0; fi
  kbool="false"; [ "$kernel" = "1" ] && kbool="true"
  printf '{"timestamp":"%s","host":"%s","action":"%s","copilot_action":true,"pid":%s,"ppid":%s,"user":"%s","cmd":"%s","exe":"%s","sha256":"%s","kernel_thread":%s}\n' \
    "$ts" "$HostName" "$ScriptName" \
    "$pid_num" "$ppid_num" \
    "$(escape_json "$user")" "$(escape_json "$cmd")" "$(escape_json "$exe")" "$(escape_json "$sha256")" \
    "$kbool" >> "$TMP_AR"
}
AddStatus() {
  ts="$(iso_now)"; st="${1:-info}"; msg="$(escape_json "${2:-}")"
  printf '{"timestamp":"%s","host":"%s","action":"%s","copilot_action":true,"status":"%s","message":"%s"}\n' \
    "$ts" "$HostName" "$ScriptName" "$st" "$msg" >> "$TMP_AR"
}

CommitNDJSON() {
  AR_DIR="$(dirname "$ARLog")"
  [ -d "$AR_DIR" ] || WriteLog "Directory missing: $AR_DIR (will attempt write anyway)" WARN
  if mv -f "$TMP_AR" "$ARLog"; then
    WriteLog "Wrote NDJSON to $ARLog" INFO
  else
    WriteLog "Primary write FAILED to $ARLog" WARN
    if mv -f "$TMP_AR" "$ARLog.new"; then
      WriteLog "Wrote NDJSON to $ARLog.new (fallback)" WARN
    else
      keep="/tmp/active-responses.$$.ndjson"
      cp -f "$TMP_AR" "$keep" 2>/dev/null || true
      WriteLog "Failed both writes; saved $keep" ERROR
      rm -f "$TMP_AR" 2>/dev/null || true
      exit 1
    fi
  fi
  for p in "$ARLog" "$ARLog.new"; do
    if [ -f "$p" ]; then
      sz=$(wc -c < "$p" 2>/dev/null || echo 0)
      ino=$(ls -li "$p" 2>/dev/null | awk '{print $1}')
      head1=$(head -n1 "$p" 2>/dev/null || true)
      WriteLog "VERIFY: path=$p inode=$ino size=${sz}B first_line=${head1:-<empty>}" INFO
    fi
  done
}

RotateLog
WriteLog "=== SCRIPT START : $ScriptName (host=$HostName) ==="
BeginNDJSON
WriteLog "Collecting running processes snapshot..."

emitted=0

for pid_dir in /proc/[0-9]*; do
  [ -d "$pid_dir" ] || continue
  pid="${pid_dir#/proc/}"

  # PPid from status (fallback 0)
  ppid="$(awk '/^PPid:/ {print $2}' "$pid_dir/status" 2>/dev/null || echo 0)"
  case "$ppid" in ''|*[!0-9]*) ppid=0 ;; esac

  # cmdline or comm; detect kernel thread (empty cmdline)
  cmdline_raw="$(tr '\0' ' ' < "$pid_dir/cmdline" 2>/dev/null || true)"
  is_kernel=0
  if [ -z "$cmdline_raw" ]; then
    is_kernel=1
    cmdline="$(cat "$pid_dir/comm" 2>/dev/null || echo "")"
  else
    cmdline="${cmdline_raw% }"
  fi

  # owner
  user="$(stat -c '%U' "$pid_dir" 2>/dev/null || echo "unknown")"

  # exe path (if real file)
  exe_path=""
  if [ -L "$pid_dir/exe" ]; then
    resolved="$(readlink -f "$pid_dir/exe" 2>/dev/null || true)"
    if [ -n "$resolved" ] && [ -f "$resolved" ]; then
      exe_path="$resolved"
    fi
  fi

  # sha256 (best-effort)
  sha256=""
  if [ -n "$exe_path" ] && [ -f "$exe_path" ]; then
    sha256="$(sha256sum "$exe_path" 2>/dev/null | awk '{print $1}' || true)"
  fi

  AddRecord "$pid" "$ppid" "$user" "$cmdline" "$exe_path" "$sha256" "$is_kernel"
  emitted=$((emitted+1))
done

# Ensure at least one line
if [ "$emitted" -eq 0 ]; then
  AddStatus "no_results" "no running processes snapshot produced"
fi

CommitNDJSON
dur=$(( $(date +%s) - runStart ))
WriteLog "=== SCRIPT END : ${dur}s ==="

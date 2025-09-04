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
  ts="$(date '+%Y-%m-%d %H:%M:%S%z')"
  line="[$ts][$level] $msg"
  printf '%s\n' "$line" >&2
  printf '%s\n' "$line" >> "$LogPath"
}

RotateLog() {
  [ -f "$LogPath" ] || return 0
  size_kb=$(awk -v s="$(wc -c <"$LogPath")" 'BEGIN{printf "%.0f", s/1024}')
  [ "$size_kb" -le "$LogMaxKB" ] && return 0
  i=$((LogKeep-1))
  while [ $i -ge 1 ]; do
    src="$LogPath.$i"; dst="$LogPath.$((i+1))"
    [ -f "$src" ] && mv -f "$src" "$dst" || true
    i=$((i-1))
  done
  mv -f "$LogPath" "$LogPath.1"
}

escape_json() {
  printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
}

BeginNDJSON() {
  TMP_AR="$(mktemp)"
}

AddRecord() {
  ts="$(date '+%Y-%m-%d %H:%M:%S%z')"
  pid="$(escape_json "$1")"
  ppid="$(escape_json "$2")"
  user="$(escape_json "$3")"
  cmd="$(escape_json "$4")"
  exe="$(escape_json "$5")"
  sha256="$(escape_json "$6")"
  kernel="${7:-0}"
  printf '{"timestamp":"%s","host":"%s","action":"%s","copilot_action":true,"pid":"%s","ppid":"%s","user":"%s","cmd":"%s","exe":"%s","sha256":"%s","kernel_thread":%s}\n' \
    "$ts" "$HostName" "$ScriptName" \
    "$pid" "$ppid" "$user" "$cmd" "$exe" "$sha256" "$kernel" >> "$TMP_AR"
}

CommitNDJSON() {
  if mv -f "$TMP_AR" "$ARLog" 2>/dev/null; then
    :
  else
    mv -f "$TMP_AR" "$ARLog.new" 2>/dev/null || printf '{"timestamp":"%s","host":"%s","action":"%s","copilot_action":true,"status":"error","message":"atomic move failed"}\n' \
      "$(date '+%Y-%m-%d %H:%M:%S%z')" "$HostName" "$ScriptName" > "$ARLog.new"
  fi
}

RotateLog
WriteLog "START $ScriptName"
BeginNDJSON
WriteLog "Collecting running processes snapshot..."

for pid_dir in /proc/[0-9]*; do
  [ -d "$pid_dir" ] || continue
  pid="${pid_dir#/proc/}"

  ppid="$(awk '/^PPid:/ {print $2}' "$pid_dir/status" 2>/dev/null || echo "")"

  cmdline_raw="$(tr '\0' ' ' < "$pid_dir/cmdline" 2>/dev/null || true)"
  is_kernel=0
  if [ -z "$cmdline_raw" ]; then
    is_kernel=1
  fi
  if [ -n "$cmdline_raw" ]; then
    cmdline="${cmdline_raw% }"
  else
    cmdline="$(cat "$pid_dir/comm" 2>/dev/null || echo "")"
  fi

  user="$(stat -c '%U' "$pid_dir" 2>/dev/null || echo "unknown")"

  exe_path=""
  if [ -L "$pid_dir/exe" ]; then
    resolved="$(readlink -f "$pid_dir/exe" 2>/dev/null || true)"
    if [ -n "$resolved" ] && [ -f "$resolved" ]; then
      exe_path="$resolved"
    fi
  fi

  sha256=""
  if [ -n "$exe_path" ] && [ -f "$exe_path" ]; then
    sha256="$(sha256sum "$exe_path" 2>/dev/null | awk '{print $1}' || echo "")"
  fi

  AddRecord "$pid" "$ppid" "$user" "$cmdline" "$exe_path" "$sha256" "$is_kernel"
done

CommitNDJSON
dur=$(( $(date +%s) - runStart ))
WriteLog "END $ScriptName in ${dur}s"

"""The runner a schedule installs on its host: one bash script per schedule, like every other script StorageForge deploys.
It holds its times already worked out, so the server's parse_cron is the only cron parser there is and hosts need no
Python. A systemd timer fires it at those times; where there is no systemd, cron wakes it each minute and --if-due decides.
"""
from __future__ import annotations

import shlex

from .scriptkit import one_line

RUNNER = r"""#!/bin/bash
# StorageForge schedule runner. Written by a deploy: change the schedule in StorageForge, not this file.
set -u
export LC_ALL=C PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
@VARS@
ETC=/etc/storageforge VAR=/var/lib/storageforge/scheduler/$SID LOCKS=/run/storageforge
if ((EUID != 0)) && [[ -n ${STORAGEFORGE_SCHED_ROOT:-} ]]; then    # tests only
  ETC=$STORAGEFORGE_SCHED_ROOT/etc VAR=$STORAGEFORGE_SCHED_ROOT/var LOCKS=$STORAGEFORGE_SCHED_ROOT/run
  PATH=$STORAGEFORGE_SCHED_ROOT/bin:$PATH
fi
TOKEN_FILE=$ETC/scheduler/$SID.token
WHY=${1:-}
case $WHY in
  --run|--timer|--if-due) ;;
  *) echo "schedule $NAME (#$SID): --run runs it now; its timer does the rest. Last run: $(tail -n 1 "$VAR/runs.jsonl" 2>/dev/null || echo none)"; exit 0 ;;
esac

within() { [[ " $1 " == *" $2 "* ]]; }
if [[ $WHY == --if-due ]]; then
  read -r m h d mo w < <(TZ=$ZONE date '+%-M %-H %-d %-m %w')
  { within "$MINS" "$m" && within "$HOURS" "$h" && within "$DOMS" "$d" && within "$MONTHS" "$mo" && within "$DOWS" "$w"; } || exit 0
fi
if [[ -n $WINDOW ]]; then
  now=$(TZ=$ZONE date +%H:%M) a=${WINDOW%-*} b=${WINDOW#*-}
  if [[ ! $a > $b ]]; then in=0; [[ ! $now < $a && $now < $b ]] && in=1
  else in=0; [[ ! $now < $a || $now < $b ]] && in=1; fi
  ((in)) || { echo "schedule $NAME: outside its window ($WINDOW)"; exit 0; }
fi
if [[ $WHY != --run ]] && ((JITTER)); then sleep $((RANDOM % (JITTER + 1))); fi

umask 077
mkdir -p "$LOCKS" "$VAR" || exit 1
chmod 0755 "$VAR" 2>/dev/null || true
exec 9>>"$LOCKS/sched-$SID.lock" || exit 1
case $POLICY in
  queue) flock 9 ;;
  replace)
    if ! flock -n 9; then
      old=$(cat "$LOCKS/sched-$SID.pid" 2>/dev/null || true)
      [[ $old =~ ^[0-9]+$ ]] && kill -TERM "$old" 2>/dev/null
      flock -w 60 9 || { echo "schedule $NAME: the running copy did not stop"; exit 0; }
    fi ;;
  *) flock -n 9 || { echo "schedule $NAME is already running"; exit 0; } ;;
esac
echo $$ >"$LOCKS/sched-$SID.pid"
out=$(mktemp "$LOCKS/out.XXXXXX") || exit 1
body=$out.body hdr=$out.hdr
trap 'rm -f "$out" "$body" "$hdr"' EXIT
child= stop=0
trap 'stop=1; [[ -n $child ]] && kill -TERM "$child" 2>/dev/null' TERM

cmd=(bash "$TASK_SH" @ARGS@)
((${#ENVS[@]})) && cmd=(env "${ENVS[@]}" "${cmd[@]}")
if [[ -n $IOCLASS ]] && command -v ionice >/dev/null; then
  if ((IOCLASS == 3)); then cmd=(ionice -c 3 "${cmd[@]}"); else cmd=(ionice -c "$IOCLASS" -n "$IOPRIO" "${cmd[@]}"); fi
fi
[[ -n $NICENESS ]] && command -v nice >/dev/null && cmd=(nice -n "$NICENESS" "${cmd[@]}")
if [[ $RUNAS != root ]] && ((EUID == 0)); then cmd=(runuser -u "$RUNAS" -- "${cmd[@]}"); fi
((TIMEOUT)) && cmd=(timeout --kill-after=30 "$TIMEOUT" "${cmd[@]}")

started=$(date +%s) attempts=0 rc=1 delay=$DELAY
while ((attempts <= RETRIES)); do
  if ((attempts)); then
    echo "retry $attempts of $RETRIES after $delay s" >>"$out"
    sleep "$delay"
    delay=$(awk -v d="$delay" -v b="$BACKOFF" 'BEGIN { printf "%d", d * b }')
  fi
  attempts=$((attempts + 1))
  if [[ $RUNAS != root ]] && ! id "$RUNAS" >/dev/null 2>&1; then
    echo "no user $RUNAS on this host" >>"$out"; rc=1; break
  fi
  ( umask 022; cd /; exec "${cmd[@]}" </dev/null >>"$out" 2>&1 9>&- ) &
  child=$!
  wait "$child"; rc=$?
  while ((stop)) && kill -0 "$child" 2>/dev/null; do wait "$child"; rc=$?; done
  child=
  { ((rc == 0)) || ((rc == 124)) || ((stop)); } && break
done
finished=$(date +%s)
nonce=$(od -An -tx1 -N16 /dev/urandom | tr -d ' \n')

# runs.jsonl is what a scan reads when a report could not get through: world-readable, so it holds no output
line=$(printf '{"schedule_id":%d,"nonce":"%s","started_at":%d,"finished_at":%d,"exit_code":%d,"attempts":%d,"no_output":true}' \
  "$SID" "$nonce" "$started" "$finished" "$rc" "$attempts")
printf '%s\n' "$line" >>"$VAR/runs.jsonl"
chmod 0644 "$VAR/runs.jsonl" 2>/dev/null || true
if (($(wc -l <"$VAR/runs.jsonl") > 600)); then tail -n 500 "$VAR/runs.jsonl" >"$VAR/runs.tmp" && mv "$VAR/runs.tmp" "$VAR/runs.jsonl"; fi
tail -c 1048576 "$out" >"$VAR/last.out"; chmod 0600 "$VAR/last.out" 2>/dev/null || true

if [[ -n $REPORT_URL && -r $TOKEN_FILE ]] && command -v curl >/dev/null; then
  utf8() { if command -v iconv >/dev/null; then iconv -c -f UTF-8 -t UTF-8; else tr -cd '\11\12\40-\176'; fi; }
  {
    printf '%s,"output":"' "${line%,\"no_output\":true\}}"
    tail -c 240000 "$out" | utf8 | tr -d '\000-\010\013-\037\177' | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e "s/$(printf '\t')/\\\\t/g" | awk '{ printf "%s\\n", $0 }'
    printf '"}'
  } >"$body"
  printf 'Authorization: Bearer %s\n' "$(cat "$TOKEN_FILE")" >"$hdr"
  ca=(); [[ -r $ETC/report-ca.pem ]] && ca=(--cacert "$ETC/report-ca.pem")   # StorageForge's self-signed certificate
  curl -fsS -m 30 ${ca[@]+"${ca[@]}"} -H @"$hdr" -H 'Content-Type: application/json' --data-binary @"$body" "$REPORT_URL/api/scheduler/report" >/dev/null 2>&1 \
    || echo "could not report to $REPORT_URL; the next scan of this host picks the run up" >&2
fi
exit "$rc"
"""


def _words(values) -> str:
    return ' '.join(str(v) for v in sorted(values))


def runner_script(schedule: dict, script_args: list[str], times: tuple, report_url: str | None, env: dict, task_sh: str) -> str:
    """The runner with this schedule's values, each as a quoted word. times: what parse_cron returned."""
    cfg, q = schedule['config'], shlex.quote
    mins, hours, doms, months, dows = times
    values = {
        'SID': int(schedule['schedule_id']), 'NAME': q(one_line(schedule['name'])), 'TASK_SH': q(task_sh), 'ZONE': q(cfg.get('timezone') or 'UTC'),
        'WINDOW': q(cfg.get('window') or ''), 'JITTER': int(cfg.get('jitter_sec') or 0), 'POLICY': q(cfg.get('concurrency_policy') or 'skip'),
        'TIMEOUT': int(cfg.get('timeout_sec') if cfg.get('timeout_sec') is not None else 3600), 'RETRIES': int(cfg.get('retry_count') or 0),
        'DELAY': int(cfg.get('retry_delay_sec') or 30), 'BACKOFF': q(str(float(cfg.get('retry_backoff') or 1.0))),
        'NICENESS': q('' if cfg.get('nice') is None else str(int(cfg['nice']))),
        'IOCLASS': {'realtime': 1, 'best-effort': 2, 'idle': 3}.get(cfg.get('ionice_class'), "''"),
        'IOPRIO': int(cfg.get('ionice_priority') if cfg.get('ionice_priority') is not None else 7), 'RUNAS': q(cfg.get('user') or 'root'),
        'REPORT_URL': q((report_url or '').rstrip('/')), 'MINS': q(_words(mins)), 'HOURS': q(_words(hours)), 'DOMS': q(_words(doms)),
        'MONTHS': q(_words(months)), 'DOWS': q(_words(dows)),
    }
    lines = [f'{k}={v}' for k, v in values.items()]
    lines.append('ENVS=(' + ' '.join(q(f'{k}={v}') for k, v in env.items()) + ')')
    return RUNNER.replace('@VARS@', '\n'.join(lines)).replace('@ARGS@', ' '.join(q(a) for a in script_args))

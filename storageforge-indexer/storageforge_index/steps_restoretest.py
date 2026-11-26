"""The restore-test plan step (roadmap section 4.2, Backup and recovery; docs/toolbox.md): the latest snapshot of a folder, restored from
a restic or Borg repository into a scratch folder, and the SHA-256 of its files compared with the folder as it is now.

Only files whose modification time is not after the snapshot are compared, since a file changed since then is meant to differ: a
sample of them (all, up to the number given), and each one that differs is a failure. A file that is not in the restore is counted
apart, since an exclude rule may have left it out on purpose. A restore that fails (a damaged repository, a wrong key) fails the test
loudly. The scratch folder is made for the run (sf-restore-XXXXXX under the folder given, which should be a dataset of its own) and
removed after it, and nothing else is written: the source is only read.

The repository key is a vault secret (field secret), brought on the runner's stdin when the plan is applied, as for every step that
names one, and kept in a root-only file (/var/lib/storageforge-tools/restore-tests/NAME.key) for the timer: restic reads it through
RESTIC_PASSWORD_FILE and Borg through BORG_PASSCOMMAND, so it is on no command line. With a schedule, the step writes a script of the same
function and a systemd timer that runs it daily or weekly. Each run writes one line, NAME.last, which the Toolbox adapter of restic and
Borg reads with the infrastructure reading: the last verified restore, shown on the tool's panel.

No apostrophes in the Bash below: the script text is checked for values that could end a quoted word.
"""
from __future__ import annotations

import posixpath
import re
import shlex

from . import changes, toolbox
from .changes import F
from .scriptkit import RELOAD_SYSTEMD

ARGS = ('name', 'tool', 'repo', 'secret', 'source', 'scratch', 'sample', 'schedule')
TOOLS = ('restic', 'borg')
SCHEDULES = ('none', 'daily', 'weekly')
RT_DIR = f'{toolbox.TOOLS_HOME}/restore-tests'
RT_LIB = '/usr/local/lib/storageforge'
UNITS = '/etc/systemd/system'
# a repository: a folder, or restic's sftp:, rest:, s3:, b2:, rclone: forms, or Borg's ssh:// and user@host:path. No space, no quote,
# never a leading dash (it would read as an option)
REPO = re.compile(r'[A-Za-z0-9_./][A-Za-z0-9_.:/@+=~-]{0,299}')

BASH = r"""
# ── restore tests (steps_restoretest.py) ─
rt_done() { # verdict message: the line the adapter reads, and the scratch folder removed
  local line
  line=$(printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s" "$(date +%s)" "$RT_NAME" "$RT_TOOL" "$1" "$RT_COMPARED" "$RT_BAD" "$RT_ABSENT" "$(printf "%s" "$2" | tr "\t\n" "  " | cut -c1-300)")
  install -d -m 0700 -- "@RTDIR@" && printf "%s\n" "$line" >"@RTDIR@/$RT_NAME.last"
  if [[ -n $RT_WORK && $RT_WORK == "$RT_SCRATCH"/sf-restore-* && -d $RT_WORK ]]; then rm -rf -- "$RT_WORK"; fi
  if [[ $1 == ok ]]; then ok "restore test $RT_NAME: $2"; else conflict "restore test $RT_NAME FAILED: $2"; fi
  return 0
}
rt_restore_test() { # name tool repo keyfile source scratch sample: restore the latest snapshot of source, compare SHA-256, record the result
  RT_NAME=$1 RT_TOOL=$2 RT_SCRATCH=$6 RT_WORK= RT_COMPARED=0 RT_BAD=0 RT_ABSENT=0
  local repo=$3 key=$4 source=${5%/} sample=${7:-200} snap= se rc=0 out f got want archive line bad=
  [[ $sample =~ ^[0-9]+$ ]] && ((sample > 0)) || sample=200
  command -v "$RT_TOOL" >/dev/null || { rt_done failed "$RT_TOOL is not installed here"; return 0; }
  [[ -r $key ]] || { rt_done failed "the repository key is not on this host"; return 0; }
  [[ -d $source ]] || { rt_done failed "$source is not a folder here, and it is what the restore is compared with"; return 0; }
  # a folder that is there is not ours to chmod: only the sf-restore-XXXXXX folder inside it is made private
  [[ -d $RT_SCRATCH ]] || install -d -m 0700 -- "$RT_SCRATCH" || { rt_done failed "could not make $RT_SCRATCH"; return 0; }
  RT_WORK=$(mktemp -d "$RT_SCRATCH/sf-restore-XXXXXX") || { RT_WORK=; rt_done failed "could not make a scratch folder in $RT_SCRATCH"; return 0; }
  case $RT_TOOL in
    restic)
      snap=$(RESTIC_REPOSITORY=$repo RESTIC_PASSWORD_FILE=$key restic snapshots --json --latest 1 --path "$source" 2>/dev/null | grep -o "\"time\":\"[^\"]*\"" | tail -n 1 | cut -d\" -f4) || true
      [[ -n $snap ]] || { rt_done failed "no snapshot of $source in the repository, or the repository cannot be read"; return 0; }
      out=$(RESTIC_REPOSITORY=$repo RESTIC_PASSWORD_FILE=$key restic restore latest --path "$source" --target "$RT_WORK" 2>&1) || rc=$?
      ;;
    borg)
      line=$(BORG_REPO=$repo BORG_PASSCOMMAND="cat $key" borg list --last 1 --format "{archive}{TAB}{time}{NL}" 2>/dev/null | tail -n 1) || true
      IFS=$'\t' read -r archive snap <<<"$line"
      [[ -n $archive && -n $snap ]] || { rt_done failed "no archive in the repository, or the repository cannot be read"; return 0; }
      out=$(cd "$RT_WORK" && BORG_REPO=$repo BORG_PASSCOMMAND="cat $key" borg extract "::$archive" "${source#/}" 2>&1) || rc=$?
      ;;
    *) rt_done failed "$RT_TOOL is not restic or borg"; return 0 ;;
  esac
  if ((rc)); then rt_done failed "the restore failed (exit $rc): $(tail -n 2 <<<"$out" | tr "\n" " ")"; return 0; fi
  se=$(date -d "$snap" +%s 2>/dev/null) || { rt_done failed "the snapshot time $snap cannot be read"; return 0; }
  info "snapshot of $(date -d "@$se" "+%F %T"), restored into $RT_WORK"
  while IFS= read -r -d "" f; do
    got=$RT_WORK$f
    if [[ ! -f $got ]]; then RT_ABSENT=$((RT_ABSENT + 1)); continue; fi
    want=$(sha256sum -- "$f" | cut -c1-64) got=$(sha256sum -- "$got" | cut -c1-64)
    RT_COMPARED=$((RT_COMPARED + 1))
    if [[ $want != "$got" ]]; then RT_BAD=$((RT_BAD + 1)); ((RT_BAD <= 5)) && bad+=" ${f#"$source"/}"; fi
  done < <(find "$source" -type f ! -newermt "@$se" -print0 2>/dev/null | shuf -z -n "$sample" 2>/dev/null)
  if ((RT_BAD)); then rt_done failed "$RT_BAD of $RT_COMPARED files differ from the source although they did not change since the snapshot:$bad"; return 0; fi
  if ((!RT_COMPARED)); then rt_done failed "nothing to compare: no file of $source older than the snapshot is in the restore"; return 0; fi
  rt_done ok "$RT_COMPARED files compared, their SHA-256 match$( ((RT_ABSENT)) && echo "; $RT_ABSENT older files are not in the backup (an exclude rule?)")"
}
rt_schedule() { # name tool repo keyfile source scratch sample schedule: a script of the same function and a timer, or none
  local name=$1 schedule=$8 script=@RTLIB@/restore-test-$1.sh unit=@UNITS@/sf-restore-test-$1 new changed=0 p=${PROBLEMS:-0}
  if [[ $schedule == none ]]; then
    if [[ -e $unit.timer ]] && act "remove the timer of restore test $name"; then
      systemctl disable --now "sf-restore-test-$name.timer" >/dev/null 2>&1 || true
      rm -f -- "$unit.timer" "$unit.service" "$script"; reload_systemd || true
    fi
    return 0
  fi
  new=$(mktemp) || { conflict "could not make a temporary file"; return 0; }
  {
    cat <<"RTEOF"
#!/usr/bin/env bash
# Written by StorageForge: a restore test, run by its timer. It reads the source, restores into a scratch folder it removes after.
set -uo pipefail
PATH=$PATH:/usr/local/bin:/usr/sbin:/sbin
APPLY=1 PROBLEMS=0
ok() { echo "ok: $*"; }; info() { echo "info: $*"; }; conflict() { echo "conflict: $*"; PROBLEMS=$((PROBLEMS + 1)); }
RTEOF
    declare -f rt_done rt_restore_test
    printf "rt_restore_test %q %q %q %q %q %q %q\nexit \$((PROBLEMS > 0))\n" "$1" "$2" "$3" "$4" "$5" "$6" "$7"
  } >"$new"
  if [[ -f $script ]] && cmp -s "$new" "$script"; then ok "$script is the restore test this plan makes"
  elif act "write $script"; then install -d -m 0755 -- "${script%/*}"; install -m 0700 -- "$new" "$script"; changed=1; fi
  rm -f -- "$new"
  new=$(printf "[Unit]\nDescription=StorageForge restore test %s\nAfter=network-online.target\n\n[Service]\nType=oneshot\nExecStart=%s\nNice=10\nIOSchedulingClass=idle\n" "$name" "$script")
  if [[ -f $unit.service && $(cat "$unit.service") == "$new" ]]; then :
  elif act "write $unit.service"; then mkdir -p -- "${unit%/*}"; printf "%s\n" "$new" >"$unit.service"; changed=1; fi
  new=$(printf "[Unit]\nDescription=StorageForge restore test %s, %s\n\n[Timer]\nOnCalendar=%s\nRandomizedDelaySec=1h\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n" "$name" "$schedule" "$schedule")
  if [[ -f $unit.timer && $(cat "$unit.timer") == "$new" ]]; then :
  elif act "write $unit.timer ($schedule)"; then printf "%s\n" "$new" >"$unit.timer"; changed=1; fi
  if ((APPLY)); then
    # also when nothing was written now but the timer is off or systemd says it has not read the units, as a run that was refused the reload leaves them;
    # a timer that is on and read needs no reload, so a dead network mount elsewhere does not fail a step with nothing to do
    if ((changed)) || ! systemctl is-enabled --quiet "sf-restore-test-$name.timer" 2>/dev/null \
      || [[ $(systemctl show -p NeedDaemonReload --value "sf-restore-test-$name.timer" "sf-restore-test-$name.service" 2>/dev/null) == *yes* ]]; then
      reload_systemd || { ((${PROBLEMS:-0} > p)) || conflict "systemd did not reload: the timer of restore test $name is not turned on"; return 0; }
    fi
    if systemctl is-enabled --quiet "sf-restore-test-$name.timer" 2>/dev/null && ((!changed)); then ok "the $schedule timer of restore test $name is on"
    else try systemctl enable --now "sf-restore-test-$name.timer" >/dev/null && ok "restore test $name runs $schedule"; fi
  fi
  return 0
}
t_restore_test() { local name=$1 tool=$2 repo=$3 secret=$4 source=$5 scratch=$6 sample=${7:-200} schedule=${8:-none} d=/run/storageforge/secrets key tmp
  ((EUID != 0)) && d=${SF_SECRET_DIR:-$d}
  key=@RTDIR@/$name.key
  if ((!APPLY)); then
    command -v "$tool" >/dev/null || later "$tool is installed by an earlier step, or from the Toolbox first"
    [[ -d $source ]] || missing "$source is not a folder here"
    missing "would: restore the latest snapshot of $source from $repo into a scratch folder under $scratch, compare the SHA-256 of up to $sample files that did not change since, and remove the scratch folder"
    [[ $schedule == none ]] || missing "would: run it $schedule with the timer sf-restore-test-$name.timer"
    [[ -f @RTDIR@/$name.last ]] && info "last result: $(cut -f4,8 "@RTDIR@/$name.last" | tr "\t" " ")"
    return 0
  fi
  if [[ -r $d/$secret ]]; then
    if [[ -f $key ]] && cmp -s -- "$d/$secret" "$key"; then ok "the repository key of $name is kept for its timer"
    else
      install -d -m 0700 -- "@RTDIR@"
      tmp=$(mktemp "@RTDIR@/.key.XXXXXX") && chmod 0600 "$tmp" && cat -- "$d/$secret" >"$tmp" && mv -f -- "$tmp" "$key" && ok "the repository key of $name is kept for its timer, root only"
    fi
  elif [[ ! -r $key ]]; then conflict "the secret $secret is not on this host: apply this plan from StorageForge, which brings it on the runner stdin"; return 0; fi
  act "restore test $name: $source from $repo" || return 0
  rt_restore_test "$name" "$tool" "$repo" "$key" "$source" "$scratch" "$sample"
  rt_schedule "$name" "$tool" "$repo" "$key" "$source" "$scratch" "$sample" "$schedule"
}
""".replace('@RTDIR@', RT_DIR).replace('@RTLIB@', RT_LIB).replace('@UNITS@', UNITS)


def _check(conn, c, h, p, say):
    if p.get('tool') not in TOOLS:
        say('crit', 'the tool is restic or borg')
    if not REPO.fullmatch(p.get('repo') or ''):
        say('crit', 'the repository is a folder or a restic or Borg repository address, with no space or quote')
    for what in ('source', 'scratch'):
        path = p.get(what) or ''
        if not path.startswith('/') or posixpath.normpath(path) != path.rstrip('/') or any(ch in path for ch in '\n\t\0'):
            say('crit', f'the {what} is an absolute folder, written out in full')
    src, scratch = (p.get('source') or '').rstrip('/'), (p.get('scratch') or '').rstrip('/')
    if scratch and not toolbox.data_folder_ok(scratch):
        say('crit', f'{scratch} is a system folder: the scratch folder should be a dataset of its own, such as /srv/restore-test')
    if src and scratch and (scratch == src or scratch.startswith(src + '/')):
        say('crit', 'the scratch folder is inside the folder it is compared with: give it a place of its own')
    if p.get('schedule') not in SCHEDULES:
        say('crit', 'the schedule is none, daily or weekly')
    say('note', f'reads {src or "the source"} and restores into a scratch folder under {scratch or "the scratch folder"}, removed after; '
                'files that did not change since the snapshot must have the same SHA-256, and one that differs fails the test')
    say('note', 'the repository key is the vault secret named, brought when the plan is applied and kept root-only for the timer; it is on no command line')
    if p.get('schedule') in ('daily', 'weekly'):
        say('note', f'runs {p["schedule"]} with the timer sf-restore-test-{p.get("name")}.timer; each result shows on the panel of {p.get("tool")}')


def _title(p) -> str:
    return f'Restore test {p.get("name")}: {p.get("source")} from {p.get("tool")}' + (f', {p["schedule"]}' if p.get('schedule') not in (None, '', 'none') else '')


def _ansible(t, conn=None):
    q = shlex.quote
    p = t['params']
    head = ('APPLY=1; ok() { echo "ok: $*"; }; missing() { echo "missing: $*"; }; conflict() { echo "conflict: $*" >&2; exit 1; }; info() { echo "$*"; }\n'
            'later() { conflict "$*"; }; act() { echo "changed: $*"; }; try() { "$@" || { conflict "failed: $*"; return 1; }; }; durable() { sync; }\n')
    words = changes.words_of(p, ARGS)
    return changes.shell_task(t, head + RELOAD_SYSTEMD + BASH + '\nt_restore_test ' + ' '.join(q(w) for w in words) + '\n')


changes.register('restore-test', {'group': 'Toolbox', 'label': 'Restore test of a backup', 'fields': [
    F('name', 'label', 'Name of the test', required=True, placeholder='photos'),
    F('tool', 'choice', 'Backup tool', options=list(TOOLS), required=True),
    F('repo', 'options', 'Repository', required=True, placeholder='/srv/backup/restic or sftp:backup@nas:/restic'),
    F('secret', 'name', 'Repository key (a vault secret)', required=True, placeholder='restic-photos'),
    F('source', 'path', 'Folder that was backed up', required=True, placeholder='/srv/photos'),
    F('scratch', 'path', 'Scratch folder (a dataset of its own)', required=True, placeholder='/srv/restore-test'),
    F('sample', 'number', 'Files to compare, at most', placeholder='200'),
    F('schedule', 'choice', 'Run it again', options=list(SCHEDULES), default='none')],
    'help': 'Restores the latest snapshot into a scratch folder and compares the SHA-256 of files that did not change since with the source. '
            'A file that differs, or a restore that fails, fails the test. The scratch folder is removed after each run.'},
    ARGS, _title, _check, _ansible)
changes.EXTRA_BASH.append(BASH)

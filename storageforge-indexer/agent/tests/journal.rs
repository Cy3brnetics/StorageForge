//! The journal reader against real journal files: written by systemd's own `systemd-journal-remote` from entries made here, in each
//! layout systemd writes (compact or regular, zstd or LZ4), and read back by systemd's own `journalctl`, which says what each entry
//! holds and what its cursor is. Where those programs are not installed the tests say so and pass: CI's builder has them.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;
use storageforge_agent::journal::{JournalFile, Position, Reader, Resume};

const REMOTE: &str = "/usr/lib/systemd/systemd-journal-remote";

fn tools() -> bool {
    let have = Path::new(REMOTE).exists() && Command::new("journalctl").arg("--version").output().is_ok_and(|o| o.status.success());
    if !have {
        eprintln!("systemd-journal-remote or journalctl is not installed: the journal reader is not checked against them here");
    }
    have
}

fn folder(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sfjournal-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Entries in journald's export format: each a list of fields, a binary one written as the format says (name, newline, length, bytes).
fn export(entries: &[(u64, Vec<(&str, Vec<u8>)>)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, (realtime, fields)) in entries.iter().enumerate() {
        out.extend(format!("__REALTIME_TIMESTAMP={realtime}\n__MONOTONIC_TIMESTAMP={}\n_BOOT_ID=0123456789abcdef0123456789abcdef\n", 1000 + i).into_bytes());
        for (name, value) in fields {
            if value.contains(&b'\n') || std::str::from_utf8(value).is_err() {
                out.extend(name.as_bytes());
                out.push(b'\n');
                out.extend((value.len() as u64).to_le_bytes());
                out.extend(value);
                out.push(b'\n');
            } else {
                out.extend(format!("{name}=").into_bytes());
                out.extend(value);
                out.push(b'\n');
            }
        }
        out.push(b'\n');
    }
    out
}

fn write_journal(dir: &Path, name: &str, env: &[(&str, &str)], entries: &[(u64, Vec<(&str, Vec<u8>)>)]) -> PathBuf {
    let input = dir.join(format!("{name}.export"));
    std::fs::write(&input, export(entries)).unwrap();
    let out = dir.join(format!("{name}.journal"));
    let done = Command::new(REMOTE).arg(format!("--output={}", out.display())).arg(&input).envs(env.iter().copied()).output().unwrap();
    assert!(done.status.success(), "{}", String::from_utf8_lossy(&done.stderr));
    out
}

/// What journalctl says of every entry of a file: its fields as JSON, and its cursor.
fn journalctl(path: &Path) -> Vec<Value> {
    let out = Command::new("journalctl").arg(format!("--file={}", path.display())).args(["-o", "json", "--all", "--no-pager"]).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8(out.stdout).unwrap().lines().map(|l| serde_json::from_str(l).unwrap()).collect()
}

fn as_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Array(bytes) => String::from_utf8_lossy(&bytes.iter().map(|b| b.as_u64().unwrap() as u8).collect::<Vec<_>>()).into_owned(),
        _ => String::new(),
    }
}

fn sample() -> Vec<(u64, Vec<(&'static str, Vec<u8>)>)> {
    let long = "a disk said something long ".repeat(60); // well past the 512 bytes past which journald compresses a field
    vec![
        (1795000000000000, vec![("MESSAGE", b"Accepted publickey for ana".to_vec()), ("PRIORITY", b"6".to_vec()), ("_SYSTEMD_UNIT", b"sshd.service".to_vec()), ("SYSLOG_IDENTIFIER", b"sshd".to_vec()),
                                ("_PID", b"42".to_vec()), ("_UID", b"0".to_vec()), ("_COMM", b"sshd".to_vec()), ("_EXE", b"/usr/bin/sshd".to_vec()), ("_CMDLINE", b"sshd --password=hunter2".to_vec())]),
        (1795000001000000, vec![("MESSAGE", long.into_bytes()), ("PRIORITY", b"3".to_vec()), ("_COMM", b"kernel".to_vec())]),
        (1795000002000000, vec![("MESSAGE", b"not \xff text".to_vec()), ("PRIORITY", b"7".to_vec())]),
        (1795000003000000, vec![("MESSAGE", b"two\nlines".to_vec()), ("PRIORITY", b"4".to_vec())]),
    ]
}

fn read_all(path: &Path) -> Vec<storageforge_agent::journal::Entry> {
    let j = JournalFile::open(path).unwrap();
    let mut pos = Position::default();
    j.new_entries(&mut pos, usize::MAX).unwrap().into_iter().map(|o| j.entry(o).unwrap()).collect()
}

#[test]
fn every_layout_systemd_writes_is_read_as_journalctl_reads_it() {
    if !tools() {
        return;
    }
    let dir = folder("layouts");
    for (name, env) in [
        ("compact-zstd", vec![("SYSTEMD_JOURNAL_COMPACT", "1"), ("SYSTEMD_JOURNAL_COMPRESS", "ZSTD")]),
        ("regular-lz4", vec![("SYSTEMD_JOURNAL_COMPACT", "0"), ("SYSTEMD_JOURNAL_COMPRESS", "LZ4")]),
        ("regular-plain", vec![("SYSTEMD_JOURNAL_COMPACT", "0"), ("SYSTEMD_JOURNAL_COMPRESS", "0"), ("SYSTEMD_JOURNAL_KEYED_HASH", "0")]),
    ] {
        let path = write_journal(&dir, name, &env, &sample());
        let ours = read_all(&path);
        let theirs = journalctl(&path);
        assert_eq!(ours.len(), theirs.len(), "{name}");
        for (e, t) in ours.iter().zip(&theirs) {
            assert_eq!(e.cursor(), t["__CURSOR"].as_str().unwrap(), "{name}: the same cursor journalctl gives");
            assert_eq!(e.seqnum.to_string(), t["__SEQNUM"].as_str().unwrap());
            assert_eq!(e.realtime.to_string(), t["__REALTIME_TIMESTAMP"].as_str().unwrap());
            let mut want = BTreeMap::new();
            for field in storageforge_agent::journal::FIELDS {
                if let Some(v) = t.get(field) {
                    want.insert(field.to_string(), as_text(v));
                }
            }
            assert_eq!(e.fields, want, "{name}");
            assert!(!e.fields.contains_key("_CMDLINE"), "never the command line");
            assert_eq!(e.unread, 0);
        }
        assert!(ours[1].fields["MESSAGE"].len() > 512, "{name}: the long field, compressed in the file, read whole");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_reader_resumes_after_a_cursor_and_reads_what_is_written_next() {
    if !tools() {
        return;
    }
    let dir = folder("resume");
    let journal = dir.join("machine");
    std::fs::create_dir_all(&journal).unwrap();
    let entries = sample();
    let path = write_journal(&journal, "system", &[], &entries[..2]);
    let first = read_all(&path);
    // from now on: nothing that was written before is handed over
    let mut tail = Reader::new(vec![journal.clone()], None);
    assert!(tail.poll().is_empty());
    // from after the first entry: the second, then nothing more
    let mut resumed = Reader::new(vec![journal.clone()], Some(Resume { seqnum_id: first[0].seqnum_id.clone(), seqnum: first[0].seqnum, realtime: first[0].realtime }));
    let got = resumed.poll();
    assert_eq!(got.iter().map(|(e, _)| e.seqnum).collect::<Vec<_>>(), [first[1].seqnum]);
    assert!(resumed.poll().is_empty());
    // more is written to the same file: both readers hand over exactly the new entries, in order, with no gap
    write_journal(&journal, "system", &[], &entries[2..]);
    let new: Vec<u64> = resumed.poll().iter().map(|(e, missing)| {
        assert_eq!(*missing, 0);
        e.seqnum
    }).collect();
    assert_eq!(new, [first[1].seqnum + 1, first[1].seqnum + 2]);
    assert_eq!(tail.poll().len(), 2);
    // a cursor whose numbering is not in any file (the journal was reset): by its time
    let mut by_time = Reader::new(vec![journal.clone()], Some(Resume { seqnum_id: "f".repeat(32), seqnum: 1, realtime: first[1].realtime }));
    assert_eq!(by_time.poll().len(), 2);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn what_is_not_a_journal_is_refused_not_followed() {
    let dir = folder("junk");
    let path = dir.join("system.journal");
    std::fs::write(&path, b"LPKSHHRH").unwrap();
    assert!(JournalFile::open(&path).is_err());
    let mut header = vec![0u8; 4096];
    header[..8].copy_from_slice(b"LPKSHHRH");
    header[12..16].copy_from_slice(&0x100u32.to_le_bytes());
    std::fs::write(&path, &header).unwrap();
    assert!(JournalFile::open(&path).err().unwrap().contains("format this plugin does not read"));
    // a header that says entries are past the end of the file
    header[12..16].copy_from_slice(&0u32.to_le_bytes());
    header[88..96].copy_from_slice(&272u64.to_le_bytes());
    header[176..184].copy_from_slice(&(1u64 << 40).to_le_bytes());
    std::fs::write(&path, &header).unwrap();
    let j = JournalFile::open(&path).unwrap();
    assert!(j.new_entries(&mut Position::default(), 10).is_err());
    let mut r = Reader::new(vec![dir.clone()], Some(Resume { seqnum_id: "0".repeat(32), seqnum: 0, realtime: 0 }));
    assert!(r.poll().is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn this_machines_own_journal_is_read_as_journalctl_reads_it() {
    // the real thing, where the test can read it: every file of this machine's journal, compact, compressed, with users' files
    let Ok(id) = std::fs::read_to_string("/etc/machine-id") else { return };
    let dir = PathBuf::from("/var/log/journal").join(id.trim());
    let Ok(file) = JournalFile::open(&dir.join("system.journal")) else {
        eprintln!("this machine's journal is not readable here: not checked");
        return;
    };
    let last = file.header.tail_entry_seqnum;
    let mut r = Reader::new(vec![dir.clone()], Some(Resume { seqnum_id: file.header.seqnum_id.clone(), seqnum: last.saturating_sub(50), realtime: 0 }));
    let got = r.poll();
    assert!(!got.is_empty());
    for pair in got.windows(2) {
        assert!(pair[0].0.seqnum < pair[1].0.seqnum, "in journald's order");
    }
    let (e, _) = &got[0];
    let out = Command::new("journalctl").args(["-o", "json", "--all", "--no-pager", "-n", "1", &format!("--cursor={}", e.cursor())]).output();
    if let Some(out) = out.ok().filter(|o| o.status.success()) {
        let line = String::from_utf8_lossy(&out.stdout);
        if let Some(first) = line.lines().next().and_then(|l| serde_json::from_str::<Value>(l).ok()) {
            assert_eq!(first["__CURSOR"].as_str().unwrap(), e.cursor());
            assert_eq!(as_text(&first["MESSAGE"]), e.fields.get("MESSAGE").cloned().unwrap_or_default());
        }
    }
}

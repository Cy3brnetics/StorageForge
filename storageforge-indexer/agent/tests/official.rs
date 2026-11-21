//! The official plugins (roadmap section 11.4), each the real program, started as the agent starts it and spoken to over its pipes
//! in the agent's framing. Each is given a folder that stands for the host's paths (the `host` of its hello), with files the kernel
//! and journald write, and what it reports is read back.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::mpsc::{channel, Receiver};
use std::time::Duration;

use serde_json::{json, Value};
use storageforge_wire::{read_frame, write_frame};

struct Plugin {
    child: Child,
    stdin: ChildStdin,
    from: Receiver<Value>,
}

impl Plugin {
    fn start(program: &str, name: &str, host: &Path, resume: Value) -> Plugin {
        let mut child = Command::new(program).env_clear().stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit()).spawn().unwrap();
        let mut stdin = child.stdin.take().unwrap();
        let mut stdout: ChildStdout = child.stdout.take().unwrap();
        write_frame(&mut stdin, json!({"op": "hello", "protocol": 1, "name": name, "host": host, "resume": resume}).to_string().as_bytes()).unwrap();
        stdin.flush().unwrap();
        let (tx, rx) = channel();
        std::thread::spawn(move || {
            while let Ok(frame) = read_frame(&mut stdout, 2, 256 << 10) {
                if tx.send(serde_json::from_slice::<Value>(&frame).unwrap()).is_err() {
                    break;
                }
            }
        });
        let p = Plugin { child, stdin, from: rx };
        assert_eq!(p.next(5)["op"], "ready", "a plugin answers hello with ready");
        p
    }

    fn next(&self, secs: u64) -> Value {
        self.from.recv_timeout(Duration::from_secs(secs)).unwrap_or(Value::Null)
    }

    /// The next reading of `kind`, skipping log lines and other kinds.
    fn reading(&self, kind: &str, secs: u64) -> Value {
        let until = std::time::Instant::now() + Duration::from_secs(secs);
        while std::time::Instant::now() < until {
            let v = self.next(1);
            if v["op"] == "data" && v["kind"] == kind {
                return v["body"].clone();
            }
        }
        panic!("no {kind} reading in {secs} s");
    }

    fn say(&mut self, v: Value) {
        write_frame(&mut self.stdin, v.to_string().as_bytes()).unwrap();
        self.stdin.flush().unwrap();
    }
}

impl Drop for Plugin {
    fn drop(&mut self) {
        let _ = write_frame(&mut self.stdin, br#"{"op":"stop"}"#);
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn folder(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sfofficial-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn put(root: &Path, path: &str, text: &str) {
    let p = root.join(path);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, text).unwrap();
}

#[test]
fn heartbeat_beats_with_nothing_of_the_host_in_it() {
    let host = folder("heartbeat");
    let p = Plugin::start(env!("CARGO_BIN_EXE_storageforge-plugin-heartbeat"), "heartbeat", &host, Value::Null);
    let beat = p.reading("beat", 5);
    assert_eq!((beat["n"].as_u64(), beat["every"].as_u64()), (Some(1), Some(10)));
    let keys: Vec<&String> = beat.as_object().unwrap().keys().collect();
    assert_eq!(keys, ["every", "n", "uptime"]);
}

#[test]
fn health_reads_proc_and_sys_and_says_whether_sshd_is_up() {
    let host = folder("health");
    put(&host, "proc/stat", "cpu  100 0 50 800 50 0 0 0 0 0\n");
    put(&host, "proc/loadavg", "0.50 0.40 0.30 1/200 300\n");
    put(&host, "proc/meminfo", "MemTotal: 1000 kB\nMemAvailable: 400 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n");
    put(&host, "proc/pressure/io", "some avg10=2.50 avg60=0 avg300=0 total=1\n");
    put(&host, "proc/mdstat", "md0 : active raid1 sdb1[1] sda1[0]\n      100 blocks [2/1] [U_]\n      [=>...]  recovery = 5.0% (5/100)\n");
    put(&host, "proc/diskstats", "   8 0 sda 10 0 0 50 10 0 0 50 0 100 100\n");
    put(&host, "proc/uptime", "1234.5 1000.0\n");
    put(&host, "proc/321/comm", "sshd\n");
    put(&host, "proc/1/net/tcp", "  sl  local_address rem_address   st\n   0: 00000000:0016 00000000:0000 0A 0\n");
    put(&host, "proc/spl/kstat/zfs/tank/state", "DEGRADED\n");
    std::fs::create_dir_all(host.join("sys/block/sda")).unwrap();
    std::fs::create_dir_all(host.join("sys/block/loop0")).unwrap();
    put(&host, "sys/fs/btrfs/1111/allocation/data/total_bytes", "1000\n");
    put(&host, "sys/fs/btrfs/1111/allocation/data/bytes_used", "600\n");
    put(&host, "sys/fs/btrfs/1111/label", "data\n");
    let p = Plugin::start(env!("CARGO_BIN_EXE_storageforge-plugin-health"), "health", &host, Value::Null);
    let h = p.reading("health", 5);
    assert_eq!(h["ssh"], json!({"process": true, "listening": [22], "read": true}));
    assert_eq!((h["md"][0]["degraded"].as_bool(), h["md"][0]["progress_pct"].as_f64()), (Some(true), Some(5.0)));
    assert_eq!(h["zfs"][0], json!({"pool": "tank", "state": "DEGRADED"}));
    assert_eq!(h["btrfs"][0]["used"], 600);
    assert_eq!(h["memory"]["MemAvailable"], 400 * 1024);
    assert_eq!(h["pressure"]["io"], 2.5);
    assert_eq!(h["uptime"], 1234);
    // sshd stops: it is said within seconds, by itself
    std::fs::remove_dir_all(host.join("proc/321")).unwrap();
    put(&host, "proc/1/net/tcp", "  sl  local_address rem_address   st\n");
    let s = p.reading("ssh", 15);
    assert_eq!(s, json!({"process": false, "listening": [], "read": true}));
}

const REMOTE: &str = "/usr/lib/systemd/systemd-journal-remote";

fn journal(dir: &Path, entries: &[(&str, &str)]) {
    let mut text = String::new();
    for (i, (priority, message)) in entries.iter().enumerate() {
        text += &format!("__REALTIME_TIMESTAMP={}\n__MONOTONIC_TIMESTAMP={}\n_BOOT_ID=0123456789abcdef0123456789abcdef\nPRIORITY={priority}\nMESSAGE={message}\n_COMM=kernel\n_CMDLINE=secret\n\n", 1795000000000000u64 + i as u64, 1000 + i);
    }
    let input = dir.join("in.export");
    std::fs::write(&input, text).unwrap();
    let out = Command::new(REMOTE).arg(format!("--output={}", dir.join("system.journal").display())).arg(&input).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    std::fs::remove_file(input).unwrap();
}

#[test]
fn logs_pushes_lines_as_they_are_written_and_resumes_where_the_controller_says() {
    if !Path::new(REMOTE).exists() {
        eprintln!("systemd-journal-remote is not installed: the logs plugin is not checked against real journal files here");
        return;
    }
    let host = folder("logs");
    let machine = "0123456789abcdef0123456789abcdef";
    put(&host, "etc/machine-id", &format!("{machine}\n"));
    let dir = host.join("var/log/journal").join(machine);
    std::fs::create_dir_all(&dir).unwrap();
    journal(&dir, &[("6", "first"), ("3", "second")]);
    // the controller has the first line already: the plugin waits for its word, and starts after it
    let mut p = Plugin::start(env!("CARGO_BIN_EXE_storageforge-plugin-logs"), "logs", &host, Value::Null);
    let first = Command::new("journalctl").arg(format!("--file={}", dir.join("system.journal").display())).args(["-o", "json", "-n", "2", "--no-pager"]).output().unwrap();
    let first: Vec<Value> = String::from_utf8_lossy(&first.stdout).lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    let seqnum_id = first[0]["__SEQNUM_ID"].as_str().unwrap().to_string();
    p.say(json!({"op": "resume", "cursor": {"s": seqnum_id, "i": 1, "t": 0}}));
    let got = p.reading("lines", 10);
    assert_eq!(got["lines"].as_array().unwrap().len(), 1);
    let line = &got["lines"][0];
    assert_eq!((line["MESSAGE"].as_str(), line["PRIORITY"].as_str(), line["__SEQNUM"].as_str()), (Some("second"), Some("3"), Some("2")));
    assert_eq!(line["__CURSOR"], first[1]["__CURSOR"], "the cursor journalctl gives the same entry");
    assert!(line.get("_CMDLINE").is_none());
    assert_eq!(got["cursor"]["i"], 2);
    // written now: pushed within seconds; a debug line is left out and counted before the next line
    journal(&dir, &[("7", "debug chatter"), ("4", "third")]);
    let got = p.reading("lines", 10);
    let line = &got["lines"][0];
    assert_eq!((line["MESSAGE"].as_str(), line["__SEQNUM"].as_str(), line["skipped"].as_u64()), (Some("third"), Some("4"), Some(1)));
    drop(p);
    // started again by the agent in the same run: where it left off, from the hello, without waiting for anyone
    journal(&dir, &[("5", "fourth")]);
    let p = Plugin::start(env!("CARGO_BIN_EXE_storageforge-plugin-logs"), "logs", &host, got["cursor"].clone());
    let again = p.reading("lines", 10);
    assert_eq!(again["lines"][0]["MESSAGE"], "fourth");
    drop(p);
    // the controller has nothing of this host yet: from what is written now
    let mut p = Plugin::start(env!("CARGO_BIN_EXE_storageforge-plugin-logs"), "logs", &host, Value::Null);
    p.say(json!({"op": "resume", "cursor": null}));
    std::thread::sleep(Duration::from_millis(1500));
    journal(&dir, &[("2", "fifth")]);
    let now = p.reading("lines", 10);
    assert_eq!(now["lines"].as_array().unwrap().iter().map(|l| l["MESSAGE"].as_str().unwrap()).collect::<Vec<_>>(), ["fifth"]);
}

#[test]
fn network_reports_traffic_and_who_is_on_the_shares() {
    let host = folder("network");
    let p = Plugin::start(env!("CARGO_BIN_EXE_storageforge-plugin-network"), "network", &host, Value::Null);
    let shares = p.reading("shares", 5);
    assert!(shares["clients"].is_array() && shares["came"].is_array() && shares["went"].is_array());
    let traffic = p.reading("traffic", 5);
    assert!(traffic["interfaces"].as_array().unwrap().iter().any(|i| i["name"] == "lo"), "{traffic}");
}

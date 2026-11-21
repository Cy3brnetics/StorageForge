//! The network plugin (roadmap section 11.4): traffic on each interface, and who is connected to the host's shares, all the time
//! rather than sampled once a scan.
//!
//! Declares the host's network namespace, so that /proc/net is the host's; nothing else. Its own sockets reach the controller and
//! nothing else, by the egress rule on `sfagent`'s uid, which holds with the host's network too.
//!
//! - `shares` every `LOOK` seconds when the clients connected to SMB (139, 445) or NFS (2049) changed, and every `EVERY` seconds
//!   anyway: each (protocol, client address) with its connections, and who came and went since the last reading.
//! - `traffic` every `EVERY` seconds: each interface's counters and the rate since the last reading.

use std::collections::BTreeMap;
use std::time::Instant;

use serde_json::{json, Value};
use storageforge_agent::hostread::{self, IfCounters};
use storageforge_agent::pluginside::Agent;

const EVERY: u64 = 60;
const LOOK: u64 = 5;

fn read(path: &str) -> String {
    use std::io::Read;
    let mut out = String::new();
    if let Ok(f) = std::fs::File::open(path) {
        let _ = f.take(16 << 20).read_to_string(&mut out);
    }
    out
}

fn clients() -> BTreeMap<(String, String), u32> {
    let mut s = hostread::tcp_sockets(&read("/proc/net/tcp"));
    s.extend(hostread::tcp_sockets(&read("/proc/net/tcp6")));
    hostread::share_clients(&s)
}

fn listed(c: &BTreeMap<(String, String), u32>) -> Vec<Value> {
    c.iter().map(|((proto, addr), n)| json!({"protocol": proto, "client": addr, "connections": n})).collect()
}

fn main() {
    let agent = match Agent::start() {
        Ok(a) => a,
        Err(why) => {
            eprintln!("{why}");
            std::process::exit(2);
        }
    };
    let mut last_clients: Option<BTreeMap<(String, String), u32>> = None;
    let mut last_traffic: Option<(Instant, BTreeMap<String, IfCounters>)> = None;
    let mut beat = 0u64;
    loop {
        let now = clients();
        let full = beat % (EVERY / LOOK) == 0;
        if full || last_clients.as_ref() != Some(&now) {
            let before = last_clients.clone().unwrap_or_default();
            let came: Vec<_> = now.keys().filter(|k| !before.contains_key(*k)).map(|(p, a)| json!({"protocol": p, "client": a})).collect();
            let went: Vec<_> = before.keys().filter(|k| !now.contains_key(*k)).map(|(p, a)| json!({"protocol": p, "client": a})).collect();
            if !agent.data("shares", json!({"clients": listed(&now), "came": came, "went": went})) {
                return;
            }
            last_clients = Some(now);
        }
        if full {
            let counters = hostread::net_dev(&read("/proc/net/dev"));
            let mut ifs = Vec::new();
            for (name, c) in counters.iter().take(256) {
                let mut v = json!({"name": name, "counters": c});
                if let Some((at, before)) = &last_traffic {
                    if let Some(b) = before.get(name) {
                        let secs = at.elapsed().as_secs_f64().max(1.0);
                        v["rx_bytes_per_s"] = json!((c.rx_bytes.saturating_sub(b.rx_bytes) as f64 / secs).round());
                        v["tx_bytes_per_s"] = json!((c.tx_bytes.saturating_sub(b.tx_bytes) as f64 / secs).round());
                    }
                }
                ifs.push(v);
            }
            if !agent.data("traffic", json!({"interfaces": ifs})) {
                return;
            }
            last_traffic = Some((Instant::now(), counters));
        }
        beat += 1;
        if !agent.sleep(LOOK as f64) {
            return;
        }
    }
}

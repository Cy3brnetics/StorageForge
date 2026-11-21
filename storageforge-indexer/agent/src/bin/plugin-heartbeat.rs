//! The heartbeat plugin (roadmap section 11.4): a beat every `EVERY` seconds, with nothing of the host in it but its uptime.
//!
//! Declares nothing: no mount, no capability, no device, no namespace, no group. While the tunnel is down its beats wait in the
//! agent's outbox, each with the time it was made, so the controller sees afterwards that the agent was alive and cut off, not dead;
//! while the tunnel is up the controller sees silence within seconds.

use serde_json::json;
use storageforge_agent::pluginside::Agent;

const EVERY: u64 = 10;

fn main() {
    let agent = match Agent::start() {
        Ok(a) => a,
        Err(why) => {
            eprintln!("{why}");
            std::process::exit(2);
        }
    };
    let mut n = 0u64;
    loop {
        n += 1;
        let uptime = std::fs::read_to_string("/proc/uptime").ok().and_then(|t| t.split_whitespace().next().and_then(|u| u.parse::<f64>().ok())).map(|u| u as u64);
        if !agent.data("beat", json!({"n": n, "every": EVERY, "uptime": uptime})) {
            break;
        }
        if !agent.sleep(EVERY as f64) {
            break;
        }
    }
}

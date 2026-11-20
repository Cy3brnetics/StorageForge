//! Prints the host firewall rule storageforge-agentctl writes for an agent with a tunnel, for the tests that load it with the real
//! nft (tests/test_agent_tunnel.py): `egress UID ADDRESS:PORT`. It is in no image.

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (Some(uid), Some(to)) = (args.first().and_then(|u| u.parse().ok()), args.get(1).and_then(|a| a.parse().ok())) else {
        eprintln!("usage: egress UID ADDRESS:PORT");
        std::process::exit(2);
    };
    print!("{}", storageforge_agent::runtime::egress_rules(uid, to));
}

//! Puts the release signers into the programs at build time.
//!
//! `release_signers` beside this file is an allowed-signers file, the format `ssh-keygen -Y verify` reads: the keys whose
//! signature makes a plugin an official one. It is compiled into storageforge-agent and storageforge-agentctl, so which code
//! may run is decided by the build and not by anything on the host or anything the controller sends.
//!
//! STORAGEFORGE_RELEASE_SIGNERS names another file for a build of one's own: the unit tests and the lab build with a key they
//! made, since nobody but the owner holds the release key. `storageforge-agent anchors` prints what a program was built with.

use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-env-changed=STORAGEFORGE_RELEASE_SIGNERS");
    let here = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let from = match std::env::var("STORAGEFORGE_RELEASE_SIGNERS") {
        Ok(path) if !path.is_empty() => PathBuf::from(path),
        _ => here.join("release_signers"),
    };
    println!("cargo:rerun-if-changed={}", from.display());
    let text = std::fs::read_to_string(&from).unwrap_or_else(|e| panic!("cannot read the release signers at {}: {e}", from.display()));
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("release_signers");
    std::fs::write(out, text).unwrap();
}

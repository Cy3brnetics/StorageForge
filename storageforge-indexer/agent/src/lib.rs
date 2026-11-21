//! StorageForge's optional agent (roadmap section 11), and storageforge-agentctl, the root helper that makes its container.
//!
//! Two static programs from one library, with no interpreter and no OpenSSL in either:
//!
//! ```text
//! storageforge-agent      in the container, as `sfagent`: reads its manifest, runs the signed plugins it names
//! storageforge-agentctl   on the host, as root, behind one sudoers line: takes signed requests and drives the runtime
//! ```
//!
//! What is here, by module:
//!
//! - `caps`       giving up root with only the capabilities the plugins declare, for a container that needs some
//! - `smart`      a disk's SMART health decoded from what it answers, in the shape smartctl prints
//! - `console`    SSH turned on for one console session on a monitoring-only host, as accounts the host's admin listed
//! - `sig`        SSH signatures made and checked in Rust: the one signature format everything uses
//! - `needs`      the whole vocabulary of what a plugin may ask of a host
//! - `plugin`     the plugin format, and who may sign one
//! - `manifest`   the host's manifest, its counter, and the rule that it gives a plugin exactly what its signer declared
//! - `identity`   the agent's own key
//! - `runner`     loading a plugin from the bytes that were checked, and the protocol on its pipes
//! - `supervise`  the agent's pass over its manifest and plugins, and the outbox of what they report
//! - `tunnel`     the encrypted tunnel to the controller: batches out, the manifest and plugins in
//! - `request`    a signed request to storageforge-agentctl
//! - `host`       what storageforge-agentctl reads from the host: accounts, groups, the machine id
//! - `runtime`    the container, as Docker, Podman or LXC is asked to make it
//! - `wipe`       wipe and stop from inside: on tampering the agent deletes its key and never starts again
//! - `outside`    wipe and stop from outside: what storageforge-agentctl's `check` compares
//!
//! The habits are the key enclave's: every input has a size limit that is checked before it is read, every structure refuses
//! fields it does not know, parsing is linear, and what no honest peer sends ends the conversation.

pub mod caps;
pub mod console;
pub mod host;
pub mod hostread;
pub mod identity;
pub mod journal;
pub mod manifest;
pub mod needs;
pub mod outside;
pub mod plugin;
pub mod pluginside;
pub mod request;
pub mod runner;
pub mod runtime;
pub mod sig;
pub mod smart;
pub mod supervise;
pub mod tunnel;
pub mod wipe;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

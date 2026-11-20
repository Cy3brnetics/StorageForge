//! Loading a plugin and running it as a child (roadmap section 11.1, "Plugins").
//!
//! A plugin is not code loaded into the agent. It is a program of its own that the agent starts and speaks to over two pipes,
//! in the framing of `storageforge-wire`, so a plugin that crashes or is taken over is not the agent.
//!
//! **Loading.** The descriptor's signature, the manifest's entry and the program's hash all have to agree (`Manifest::
//! admit_plugin`). The program's bytes are read once into a sealed memory file, hashed there, and run from there: what was checked
//! is what runs, whatever happens to the file in the plugin folder afterwards.
//!
//! **Running.** The child gets an empty environment, the three pipes and no other open file, cannot gain privileges
//! (`no_new_privs`), holds no ambient capability unless its descriptor declares one, and dies with the agent.
//!
//! **The protocol** (version 1). Every message is one frame of JSON, at most `MAX_MESSAGE` bytes.
//!
//! ```text
//! agent  -> plugin   {"op":"hello","protocol":1,"name":"NAME","host":"/host"}     first, once
//! plugin -> agent    {"op":"ready"}                                               its answer
//! plugin -> agent    {"op":"data","kind":"KIND","body":{...}}                     a reading, as often as it has one
//! plugin -> agent    {"op":"log","text":"..."}                                    a line for the agent's own log
//! agent  -> plugin   {"op":"stop"}                                                finish and exit
//! ```
//!
//! Anything else from a plugin, a frame that is too large, or more than `MESSAGES_PER_MINUTE`, ends it: no honest plugin does
//! that. What a plugin reports is a claim about this host and nothing more; the agent passes it on under its own key and the
//! receiver (roadmap section 11.2) decides what it is worth.

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use storageforge_wire::{read_frame, write_frame, FrameError};

use crate::identity::read_small;
use crate::manifest::{Entry, Manifest};
use crate::plugin::{self, Anchors, Descriptor};
use crate::sig;

/// The most one message from a plugin may be.
pub const MAX_MESSAGE: usize = 256 << 10;
/// How many messages a plugin may send in a minute before it is stopped.
pub const MESSAGES_PER_MINUTE: u32 = 6000;
/// Where the host's paths are mounted in the container.
pub const HOST_ROOT: &str = "/host";

pub fn descriptor_file(name: &str) -> String {
    format!("{name}.plugin.json")
}

pub fn signature_file(name: &str) -> String {
    format!("{name}.plugin.sig")
}

pub fn program_file(name: &str) -> String {
    format!("{name}.plugin")
}

/// A plugin that passed every check, with its program held in memory.
#[derive(Debug)]
pub struct Loaded {
    pub descriptor: Descriptor,
    program: File,
}

fn sealed_copy(name: &str, mut from: impl Read, size: u64) -> Result<(File, String), String> {
    let label = std::ffi::CString::new(format!("sfplugin-{name}")).map_err(|_| "bad name")?;
    const MFD_EXEC: libc::c_uint = 0x10;
    let mut fd = unsafe { libc::memfd_create(label.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING | MFD_EXEC) };
    if fd < 0 {
        // a kernel from before 6.3 does not know MFD_EXEC, and there a memory file can be run without it
        fd = unsafe { libc::memfd_create(label.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) };
    }
    if fd < 0 {
        return Err(format!("cannot make a memory file: {}", std::io::Error::last_os_error()));
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    let mut hash = Sha256::new();
    let mut buf = vec![0u8; 64 << 10];
    let mut total = 0u64;
    loop {
        let n = from.read(&mut buf).map_err(|e| format!("cannot read the program: {e}"))?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > size {
            return Err("the program is larger than its descriptor says".into());
        }
        hash.update(&buf[..n]);
        file.write_all(&buf[..n]).map_err(|e| format!("cannot copy the program: {e}"))?;
    }
    if total != size {
        return Err("the program is smaller than its descriptor says".into());
    }
    if unsafe { libc::fchmod(fd, 0o500) } != 0 {
        return Err(format!("cannot make the copy runnable: {}", std::io::Error::last_os_error()));
    }
    let seals = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    if unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, seals) } != 0 {
        return Err(format!("cannot seal the copy: {}", std::io::Error::last_os_error()));
    }
    // A file that is open for writing cannot be run ("text file busy"): the sealed copy is opened again for reading, and the
    // descriptor it was written through is closed when `file` goes.
    let sealed = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_CLOEXEC).open(format!("/proc/self/fd/{fd}")).map_err(|e| format!("cannot open the sealed copy: {e}"))?;
    Ok((sealed, hash.finalize().iter().map(|b| format!("{b:02x}")).collect()))
}

/// Loads the plugin `entry` names from `dir`, or says why it is refused.
pub fn load(dir: &Path, entry: &Entry, anchors: &Anchors) -> Result<Loaded, String> {
    let name = &entry.name;
    if !plugin::is_name(name) {
        return Err("not a plugin name".into());
    }
    let missing = |what: &str, e: std::io::Error| format!("plugin {name}: its {what} is not in the plugin folder as a plain file ({e})");
    let bytes = read_small(&dir.join(descriptor_file(name)), plugin::MAX_DESCRIPTOR).map_err(|e| missing("descriptor", e))?;
    let signature = read_small(&dir.join(signature_file(name)), sig::MAX_SIGNATURE).map_err(|e| missing("signature", e))?;
    let signature = String::from_utf8(signature).map_err(|_| format!("plugin {name}: its signature is not text"))?;
    let descriptor = Manifest::admit_plugin(entry, &bytes, &signature, anchors)?;
    if descriptor.arch != plugin::this_arch() {
        return Err(format!("plugin {name}: it is built for {}, and this is {}", descriptor.arch, plugin::this_arch()));
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(dir.join(program_file(name)))
        .map_err(|e| missing("program", e))?;
    let meta = file.metadata().map_err(|e| missing("program", e))?;
    if !meta.is_file() || meta.len() != descriptor.size {
        return Err(format!("plugin {name}: its program is not a plain file of the size its descriptor says"));
    }
    let (program, sha256) = sealed_copy(name, file, descriptor.size).map_err(|why| format!("plugin {name}: {why}"))?;
    if sha256 != descriptor.sha256 {
        return Err(format!("plugin {name}: its program is not the one that was signed"));
    }
    Ok(Loaded { descriptor, program })
}

/// Starts a loaded plugin. Its stdin, stdout and stderr are pipes.
pub fn spawn(loaded: &Loaded) -> std::io::Result<Child> {
    let fd = loaded.program.as_raw_fd();
    let keeps_capabilities = !loaded.descriptor.needs.capabilities.is_empty();
    let mut command = Command::new(format!("/proc/self/fd/{fd}"));
    command.arg0(format!("sfplugin-{}", loaded.descriptor.name)).env_clear().current_dir("/").stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    unsafe {
        // Between fork and exec, in the child: only calls that are safe there, and a failure of any of them stops the start.
        command.pre_exec(move || {
            let must = |rc: libc::c_int| if rc == 0 { Ok(()) } else { Err(std::io::Error::last_os_error()) };
            must(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))?;
            must(libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0))?;
            if !keeps_capabilities {
                must(libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0))?;
            }
            let none = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
            must(libc::setrlimit(libc::RLIMIT_CORE, &none))?;
            let files = libc::rlimit { rlim_cur: 256, rlim_max: 256 };
            must(libc::setrlimit(libc::RLIMIT_NOFILE, &files))?;
            Ok(())
        });
    }
    command.spawn()
}

/// What a plugin may say.
#[derive(Debug, PartialEq)]
pub enum Message {
    Ready,
    Data { kind: String, body: Value },
    Log(String),
}

/// Why a plugin's stream ended.
#[derive(Debug, PartialEq, Eq)]
pub enum Hangup {
    /// It closed its end, which is how a plugin that exits ends.
    Closed,
    /// It sent what no honest plugin sends. The text says what, and holds nothing the plugin wrote.
    Refused(&'static str),
}

/// Text from a plugin made safe for a log line: printable ASCII and spaces, cut at 500 characters.
pub fn plain(text: &str) -> String {
    text.chars().take(500).map(|c| if c.is_ascii_graphic() || c == ' ' { c } else { '?' }).collect()
}

/// The next message of a plugin.
pub fn read_message(from: &mut impl Read) -> Result<Message, Hangup> {
    let frame = match read_frame(from, 2, MAX_MESSAGE) {
        Ok(frame) => frame,
        Err(FrameError::Io(_)) => return Err(Hangup::Closed),
        Err(FrameError::Size(_)) => return Err(Hangup::Refused("a frame of a size no plugin sends")),
    };
    let Ok(Value::Object(mut v)) = serde_json::from_slice::<Value>(&frame) else {
        return Err(Hangup::Refused("a frame that is not a JSON object"));
    };
    let op = v.get("op").and_then(Value::as_str).unwrap_or("").to_string();
    match (op.as_str(), v.len()) {
        ("ready", 1) => Ok(Message::Ready),
        ("log", 2) => match v.remove("text") {
            Some(Value::String(text)) => Ok(Message::Log(plain(&text))),
            _ => Err(Hangup::Refused("a log message without text")),
        },
        ("data", 3) => {
            let kind = match v.remove("kind") {
                Some(Value::String(kind)) if plugin::is_name(&kind) => kind,
                _ => return Err(Hangup::Refused("a data message without a proper kind")),
            };
            match v.remove("body") {
                Some(body @ Value::Object(_)) => Ok(Message::Data { kind, body }),
                _ => Err(Hangup::Refused("a data message whose body is not an object")),
            }
        }
        _ => Err(Hangup::Refused("a message that is not ready, data or log")),
    }
}

pub fn hello(name: &str) -> Vec<u8> {
    json!({"op": "hello", "protocol": plugin::PROTOCOL, "name": name, "host": HOST_ROOT}).to_string().into_bytes()
}

pub fn send(to: &mut impl Write, message: &[u8]) -> std::io::Result<()> {
    write_frame(to, message)
}

/// Counts messages against `MESSAGES_PER_MINUTE`.
pub struct Rate {
    window: u64,
    count: u32,
}

impl Rate {
    pub fn new() -> Rate {
        Rate { window: 0, count: 0 }
    }

    /// Whether one more message at `now` (seconds) is within the limit.
    pub fn allow(&mut self, now: u64) -> bool {
        if now / 60 != self.window {
            self.window = now / 60;
            self.count = 0;
        }
        self.count += 1;
        self.count <= MESSAGES_PER_MINUTE
    }
}

impl Default for Rate {
    fn default() -> Self {
        Rate::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn framed(text: &str) -> Vec<u8> {
        let mut out = Vec::new();
        write_frame(&mut out, text.as_bytes()).unwrap();
        out
    }

    #[test]
    fn a_plugin_says_three_things_and_nothing_else() {
        assert_eq!(read_message(&mut &framed(r#"{"op":"ready"}"#)[..]), Ok(Message::Ready));
        assert_eq!(read_message(&mut &framed(r#"{"op":"log","text":"hello\u001b[31m\nthere"}"#)[..]), Ok(Message::Log("hello?[31m?there".into())));
        assert_eq!(
            read_message(&mut &framed(r#"{"op":"data","kind":"heartbeat","body":{"n":1}}"#)[..]),
            Ok(Message::Data { kind: "heartbeat".into(), body: json!({"n": 1}) })
        );
        for bad in [
            r#"{"op":"exec","argv":["sh"]}"#,
            r#"{"op":"ready","extra":1}"#,
            r#"{"op":"data","kind":"../x","body":{}}"#,
            r#"{"op":"data","kind":"k","body":"text"}"#,
            r#"{"op":"data","kind":"k","body":{},"host":"another"}"#,
            r#"{"op":"log","text":5}"#,
            r#"["ready"]"#,
            "not json",
        ] {
            assert!(matches!(read_message(&mut &framed(bad)[..]), Err(Hangup::Refused(_))), "{bad}");
        }
        assert_eq!(read_message(&mut &[][..]), Err(Hangup::Closed));
        let mut large = ((MAX_MESSAGE + 1) as u32).to_be_bytes().to_vec();
        large.extend_from_slice(b"{}");
        assert!(matches!(read_message(&mut &large[..]), Err(Hangup::Refused(_))));
    }

    #[test]
    fn a_flood_is_counted_by_the_minute() {
        let mut rate = Rate::new();
        assert!((0..MESSAGES_PER_MINUTE).all(|_| rate.allow(120)));
        assert!(!rate.allow(121));
        assert!(rate.allow(180), "the next minute starts again");
    }
}

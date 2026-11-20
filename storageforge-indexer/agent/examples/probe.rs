//! A plugin for the tests, and the smallest example of one: it speaks the protocol of `runner` and reports what it was started
//! with. It is no official plugin and is in no image.
//!
//! How it behaves follows the name it is told in `hello`, since a plugin gets no arguments and no environment:
//!
//!   probe   ready, one `probe` reading (its uid, how many environment variables and open files it has, whether it can gain
//!           privileges), one log line, then it waits for `stop`
//!   early   a reading before `ready`, which the agent stops it for
//!   rude    a message that is none of the three, which the agent stops it for
//!   quit    ready, then it exits

use std::io::{stdin, stdout};

use storageforge_wire::{read_frame, write_frame, MAX_FRAME};

fn say(text: &str) {
    let _ = write_frame(&mut stdout().lock(), text.as_bytes());
}

fn main() {
    let Ok(hello) = read_frame(&mut stdin().lock(), 2, MAX_FRAME) else { return };
    let hello = String::from_utf8_lossy(&hello).into_owned();
    let name = hello.split("\"name\":\"").nth(1).and_then(|rest| rest.split('"').next()).unwrap_or("").to_string();
    match name.as_str() {
        "early" => say(r#"{"op":"data","kind":"probe","body":{}}"#),
        "rude" => {
            say(r#"{"op":"ready"}"#);
            say(r#"{"op":"exec","argv":["sh"]}"#);
        }
        "quit" => say(r#"{"op":"ready"}"#),
        _ => {
            say(r#"{"op":"ready"}"#);
            let fds = std::fs::read_dir("/proc/self/fd").map(|d| d.count()).unwrap_or(0);
            let no_new_privs = std::fs::read_to_string("/proc/self/status").unwrap_or_default().lines().any(|l| l.starts_with("NoNewPrivs:") && l.ends_with('1'));
            let uid = std::fs::read_to_string("/proc/self/status").unwrap_or_default().lines().find(|l| l.starts_with("Uid:")).and_then(|l| l.split_whitespace().nth(2).map(str::to_string)).unwrap_or_default();
            say(&format!(r#"{{"op":"data","kind":"probe","body":{{"uid":"{uid}","env":{},"fds":{fds},"no_new_privs":{no_new_privs},"args":{}}}}}"#, std::env::vars_os().count(), std::env::args_os().count()));
            say(r#"{"op":"log","text":"probe is up"}"#);
            eprintln!("a line on stderr");
            // until the agent says stop, or goes away
            let _ = read_frame(&mut stdin().lock(), 2, MAX_FRAME);
        }
    }
}

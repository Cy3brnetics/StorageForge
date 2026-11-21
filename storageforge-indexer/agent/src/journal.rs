//! Reading systemd's journal files directly, for the logs plugin (roadmap section 3, phase 2). The agent's image has no
//! `journalctl` and no libsystemd, so the files are read here, as systemd documents them (JOURNAL_FILE_FORMAT): the header, the
//! chain of entry arrays, each entry and the data objects it names. Regular and compact files, keyed hashes or not, data compressed
//! with zstd or LZ4 (each in pure Rust). Data compressed with xz, which systemd has not written by default for years, is not read:
//! such a field is shown as not read, and counted.
//!
//! Nothing here trusts the file: every offset is checked against the file's size, every object against the size its header says
//! and a ceiling, and an entry that cannot be read is skipped and counted, never followed. A file is read with `pread`, never mapped,
//! so a file that shrinks under it gives errors, not a crash.
//!
//! A journald on the host writes several files (the system's, each user's) and numbers every entry in all of them from one counter,
//! `seqnum`, under one `seqnum_id`. `Reader` reads all the files of one machine's folder, new entries as they are written, and hands
//! them over in that order, which is also how a gap is seen: a number that never comes was deleted on the host.

use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

const SIGNATURE: &[u8; 8] = b"LPKSHHRH";
const HEADER_MIN: u64 = 208;
const INCOMPATIBLE_XZ: u32 = 1;
const INCOMPATIBLE_LZ4: u32 = 2;
const INCOMPATIBLE_KEYED_HASH: u32 = 4;
const INCOMPATIBLE_ZSTD: u32 = 8;
const INCOMPATIBLE_COMPACT: u32 = 16;
const KNOWN_INCOMPATIBLE: u32 = INCOMPATIBLE_XZ | INCOMPATIBLE_LZ4 | INCOMPATIBLE_KEYED_HASH | INCOMPATIBLE_ZSTD | INCOMPATIBLE_COMPACT;
const OBJECT_DATA: u8 = 1;
const OBJECT_ENTRY: u8 = 3;
const OBJECT_ENTRY_ARRAY: u8 = 6;
const COMPRESSED_XZ: u8 = 1;
const COMPRESSED_LZ4: u8 = 2;
const COMPRESSED_ZSTD: u8 = 4;
/// The most one object may be, and the most a field may be once uncompressed: larger ones are not read.
const MAX_OBJECT: u64 = 16 << 20;
const MAX_FIELD: usize = 64 << 10;
/// The most items an entry may have.
const MAX_ITEMS: u64 = 4096;

/// The fields kept from each entry. Never `_CMDLINE`, where passwords sit.
pub const FIELDS: [&str; 9] = ["MESSAGE", "PRIORITY", "_SYSTEMD_UNIT", "SYSLOG_IDENTIFIER", "_PID", "_UID", "_COMM", "_EXE", "_TRANSPORT"];

fn le64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// What a journal file's header says, as far as reading needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub incompatible: u32,
    pub state: u8,
    pub file_id: String,
    pub machine_id: String,
    pub seqnum_id: String,
    pub header_size: u64,
    pub arena_size: u64,
    pub n_entries: u64,
    pub tail_entry_seqnum: u64,
    pub head_entry_seqnum: u64,
    pub entry_array_offset: u64,
    pub head_entry_realtime: u64,
    pub tail_entry_realtime: u64,
}

/// One entry: its place in the journal, and the fields kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub seqnum_id: String,
    pub seqnum: u64,
    pub realtime: u64,
    pub monotonic: u64,
    pub boot_id: String,
    pub xor_hash: u64,
    pub fields: BTreeMap<String, String>,
    /// Fields that were there and could not be read (compressed with xz, too large, damaged).
    pub unread: u32,
}

impl Entry {
    /// The cursor journalctl gives this entry, word for word, so that a line read here and the same line read over SSH by a scan
    /// are known for one.
    pub fn cursor(&self) -> String {
        format!("s={};i={:x};b={};m={:x};t={:x};x={:x}", self.seqnum_id, self.seqnum, self.boot_id, self.monotonic, self.realtime, self.xor_hash)
    }

    pub fn priority(&self) -> u8 {
        self.fields.get("PRIORITY").and_then(|p| p.trim().parse().ok()).filter(|p| *p <= 7).unwrap_or(6)
    }
}

/// One journal file, open.
pub struct JournalFile {
    file: File,
    pub path: PathBuf,
    pub header: Header,
    compact: bool,
    size: u64,
}

impl JournalFile {
    pub fn open(path: &Path) -> Result<JournalFile, String> {
        use std::os::unix::fs::OpenOptionsExt;
        let file = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let mut j = JournalFile { file, path: path.to_path_buf(), header: Header::default_empty(), compact: false, size: 0 };
        j.refresh()?;
        Ok(j)
    }

    /// Reads the header again: a file that journald writes grows, and says so in its header.
    pub fn refresh(&mut self) -> Result<(), String> {
        self.size = self.file.metadata().map_err(|e| e.to_string())?.len();
        let mut b = vec![0u8; 272];
        let n = self.file.read_at(&mut b, 0).map_err(|e| e.to_string())?;
        if n < HEADER_MIN as usize || &b[..8] != SIGNATURE {
            return Err(format!("{} is not a journal file", self.path.display()));
        }
        let incompatible = le32(&b, 12);
        if incompatible & !KNOWN_INCOMPATIBLE != 0 {
            return Err(format!("{} has a format this plugin does not read (flags {incompatible:#x})", self.path.display()));
        }
        let h = Header {
            incompatible,
            state: b[16],
            file_id: hex(&b[24..40]),
            machine_id: hex(&b[40..56]),
            seqnum_id: hex(&b[72..88]),
            header_size: le64(&b, 88),
            arena_size: le64(&b, 96),
            n_entries: le64(&b, 152),
            tail_entry_seqnum: le64(&b, 160),
            head_entry_seqnum: le64(&b, 168),
            entry_array_offset: le64(&b, 176),
            head_entry_realtime: le64(&b, 184),
            tail_entry_realtime: le64(&b, 192),
        };
        if h.header_size < HEADER_MIN || h.header_size > 4096 {
            return Err(format!("{} has a header of a size this plugin does not read", self.path.display()));
        }
        self.compact = incompatible & INCOMPATIBLE_COMPACT != 0;
        self.header = h;
        Ok(())
    }

    /// One object: its type, flags and payload (after the 16 bytes of its header). Checked against the file and the ceiling.
    fn object(&self, offset: u64, want: u8) -> Result<(u8, Vec<u8>), String> {
        if offset < self.header.header_size || offset % 8 != 0 || offset.saturating_add(16) > self.size {
            return Err("an offset outside the file".into());
        }
        let mut head = [0u8; 16];
        self.file.read_exact_at(&mut head, offset).map_err(|e| e.to_string())?;
        let size = le64(&head, 8);
        if head[0] != want || size < 16 || size > MAX_OBJECT || offset.saturating_add(size) > self.size {
            return Err("an object that is not what it should be".into());
        }
        let mut payload = vec![0u8; (size - 16) as usize];
        self.file.read_exact_at(&mut payload, offset + 16).map_err(|e| e.to_string())?;
        Ok((head[1], payload))
    }

    /// The offsets of the entries in one entry array, and where the next array is. Unused slots at the end are zero.
    fn entry_array(&self, offset: u64) -> Result<(Vec<u64>, u64), String> {
        let (_, p) = self.object(offset, OBJECT_ENTRY_ARRAY)?;
        if p.len() < 8 {
            return Err("an entry array too small".into());
        }
        let next = le64(&p, 0);
        let items = &p[8..];
        let out: Vec<u64> = if self.compact { items.chunks_exact(4).map(|c| u32::from_le_bytes(c.try_into().unwrap()) as u64).collect() } else { items.chunks_exact(8).map(|c| u64::from_le_bytes(c.try_into().unwrap())).collect() };
        Ok((out.into_iter().take_while(|o| *o != 0).collect(), next))
    }

    /// Up to `most` entries' offsets after `pos`, in order, and `pos` moved past them. Positions are (array offset, index in it), so
    /// that the next call reads only what is new: journald fills an array's slots in place, and then links the next array.
    pub fn new_entries(&self, pos: &mut Position, most: usize) -> Result<Vec<u64>, String> {
        let mut out = Vec::new();
        if pos.array == 0 {
            pos.array = self.header.entry_array_offset;
            pos.index = 0;
            if pos.array == 0 {
                return Ok(out);
            }
        }
        let mut hops = 0;
        loop {
            let (items, next) = self.entry_array(pos.array)?;
            if pos.index < items.len() {
                let take = (items.len() - pos.index).min(most - out.len());
                out.extend_from_slice(&items[pos.index..pos.index + take]);
                pos.index += take;
                if out.len() >= most {
                    return Ok(out);
                }
            }
            if next == 0 || items.len() < self.capacity(pos.array)? {
                return Ok(out);
            }
            pos.array = next;
            pos.index = 0;
            hops += 1;
            if hops > 1_000_000 {
                return Err("an entry array chain without end".into());
            }
        }
    }

    fn capacity(&self, array: u64) -> Result<usize, String> {
        let mut head = [0u8; 16];
        self.file.read_exact_at(&mut head, array).map_err(|e| e.to_string())?;
        let item = if self.compact { 4 } else { 8 };
        Ok(((le64(&head, 8).saturating_sub(24)) / item) as usize)
    }

    /// The entry at `offset`, with the fields in `FIELDS`.
    pub fn entry(&self, offset: u64) -> Result<Entry, String> {
        let (_, p) = self.object(offset, OBJECT_ENTRY)?;
        if p.len() < 48 {
            return Err("an entry too small".into());
        }
        let mut e = Entry {
            seqnum_id: self.header.seqnum_id.clone(),
            seqnum: le64(&p, 0),
            realtime: le64(&p, 8),
            monotonic: le64(&p, 16),
            boot_id: hex(&p[24..40]),
            xor_hash: le64(&p, 40),
            fields: BTreeMap::new(),
            unread: 0,
        };
        let item = if self.compact { 4 } else { 16 };
        let items = &p[48..];
        if (items.len() / item) as u64 > MAX_ITEMS {
            return Err("an entry with more fields than any honest one".into());
        }
        for chunk in items.chunks_exact(item) {
            let data = if self.compact { u32::from_le_bytes(chunk[..4].try_into().unwrap()) as u64 } else { u64::from_le_bytes(chunk[..8].try_into().unwrap()) };
            match self.field(data) {
                Ok(Some((name, value))) => {
                    e.fields.entry(name).or_insert(value);
                }
                Ok(None) => {}
                Err(_) => e.unread += 1,
            }
        }
        Ok(e)
    }

    /// A data object as `NAME=value`, when NAME is one of `FIELDS`; None for the others.
    fn field(&self, offset: u64) -> Result<Option<(String, String)>, String> {
        let (flags, p) = self.object(offset, OBJECT_DATA)?;
        let at = if self.compact { 56 } else { 48 };
        if p.len() < at {
            return Err("a data object too small".into());
        }
        let raw = &p[at..];
        let bytes = match flags & (COMPRESSED_XZ | COMPRESSED_LZ4 | COMPRESSED_ZSTD) {
            0 => raw.to_vec(),
            COMPRESSED_ZSTD => zstd(raw)?,
            COMPRESSED_LZ4 => lz4(raw)?,
            _ => return Err("compressed with xz".into()),
        };
        let Some(eq) = bytes.iter().position(|b| *b == b'=') else { return Err("a field without =".into()) };
        let name = std::str::from_utf8(&bytes[..eq]).map_err(|_| "a field name that is not text")?;
        if !FIELDS.contains(&name) {
            return Ok(None);
        }
        Ok(Some((name.to_string(), String::from_utf8_lossy(&bytes[eq + 1..]).into_owned())))
    }
}

impl Header {
    fn default_empty() -> Header {
        Header {
            incompatible: 0,
            state: 0,
            file_id: String::new(),
            machine_id: String::new(),
            seqnum_id: String::new(),
            header_size: 0,
            arena_size: 0,
            n_entries: 0,
            tail_entry_seqnum: 0,
            head_entry_seqnum: 0,
            entry_array_offset: 0,
            head_entry_realtime: 0,
            tail_entry_realtime: 0,
        }
    }
}

fn zstd(raw: &[u8]) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let mut decoder = ruzstd::decoding::StreamingDecoder::new(raw).map_err(|e| format!("zstd: {e}"))?;
    let mut out = Vec::new();
    (&mut decoder).take(MAX_FIELD as u64 + 1).read_to_end(&mut out).map_err(|e| format!("zstd: {e}"))?;
    if out.len() > MAX_FIELD {
        out.truncate(MAX_FIELD);
    }
    Ok(out)
}

/// journald's LZ4: the uncompressed size as 8 bytes, little-endian, then one LZ4 block.
fn lz4(raw: &[u8]) -> Result<Vec<u8>, String> {
    if raw.len() < 8 {
        return Err("lz4: too short".into());
    }
    let size = le64(raw, 0);
    if size > MAX_OBJECT {
        return Err("lz4: larger than a field may be".into());
    }
    let mut out = lz4_flex::block::decompress(&raw[8..], size as usize).map_err(|e| format!("lz4: {e}"))?;
    out.truncate(MAX_FIELD);
    Ok(out)
}

/// Where reading a file is: the entry array, and the index in it, of the next entry to read.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Position {
    pub array: u64,
    pub index: usize,
}

/// Where the logs plugin resumes: the journal's numbering, and the time as a fallback when that numbering is gone (the journal
/// was reset, or the files that held it were deleted).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resume {
    pub seqnum_id: String,
    pub seqnum: u64,
    pub realtime: u64,
}

struct Tracked {
    file: JournalFile,
    pos: Position,
    /// Entries read from this file and not handed over yet, oldest first.
    peeked: std::collections::VecDeque<Entry>,
    done: bool,
}

/// All the journal files of one machine's folders, read as they grow and merged into one stream in journald's own order.
pub struct Reader {
    dirs: Vec<PathBuf>,
    files: HashMap<String, Tracked>,
    /// The last number handed over, per seqnum_id.
    last: HashMap<String, u64>,
    start: Option<Resume>,
    at_tail: bool,
    /// How many polls the stream has waited at a missing number.
    held: u32,
    pub unreadable: u64,
}

/// How many polls the stream waits at a missing number while a file that is being written has nothing more to read yet: the entry
/// may be written into that file a moment later. After that it goes on, and the number is a gap: deleted on the host, or in a file
/// this plugin cannot read.
const HOLD_POLLS: u32 = 2;
/// How many entries one poll hands over at most, and reads from one file at a time.
pub const POLL_ENTRIES: usize = 2000;
const READ_AHEAD: usize = 256;

impl Reader {
    /// Reads `dirs` (the machine's folders under /var/log/journal and /run/log/journal), from just after `start`, or from what is
    /// written from now on when there is none.
    pub fn new(dirs: Vec<PathBuf>, start: Option<Resume>) -> Reader {
        let at_tail = start.is_none();
        Reader { dirs, files: HashMap::new(), last: HashMap::new(), start, at_tail, held: 0, unreadable: 0 }
    }

    fn discover(&mut self) {
        let mut found = Vec::new();
        for dir in &self.dirs {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for e in entries.flatten().take(10_000) {
                    let name = e.file_name().to_string_lossy().into_owned();
                    // `.journal~` files are ones journald found damaged and put aside
                    if name.ends_with(".journal") && e.file_type().is_ok_and(|t| t.is_file()) {
                        found.push(e.path());
                    }
                }
            }
        }
        found.sort();
        for path in found {
            let Ok(file) = JournalFile::open(&path) else {
                self.unreadable += 1;
                continue;
            };
            if self.files.contains_key(&file.header.file_id) {
                continue;
            }
            let mut tracked = Tracked { pos: Position::default(), peeked: Default::default(), done: false, file };
            if self.place(&mut tracked).is_err() {
                self.unreadable += 1;
                continue;
            }
            self.files.insert(tracked.file.header.file_id.clone(), tracked);
        }
    }

    /// Where reading a file begins: after the resume point, or at its end when reading from now on.
    fn place(&self, t: &mut Tracked) -> Result<(), String> {
        let h = t.file.header.clone();
        let skip_all = match &self.start {
            None => self.at_tail,
            Some(r) if r.seqnum_id == h.seqnum_id => h.tail_entry_seqnum <= r.seqnum,
            Some(r) => h.tail_entry_realtime <= r.realtime,
        };
        let mut end = Position::default();
        let offsets = t.file.new_entries(&mut end, usize::MAX)?;
        if skip_all {
            t.pos = end;
            return Ok(());
        }
        // the first entry after the resume point, found by halving: entries are in order in their file
        let after = |e: &Entry| match &self.start {
            Some(r) if r.seqnum_id == h.seqnum_id => e.seqnum > r.seqnum,
            Some(r) => e.realtime > r.realtime,
            None => true,
        };
        let (mut lo, mut hi) = (0usize, offsets.len());
        while lo < hi {
            let mid = (lo + hi) / 2;
            match t.file.entry(offsets[mid]) {
                Ok(e) if after(&e) => hi = mid,
                _ => lo = mid + 1,
            }
        }
        // the position of entry `lo`: the arrays walked again, `lo` entries in
        let mut p = Position::default();
        t.file.new_entries(&mut p, lo)?;
        t.pos = p;
        Ok(())
    }

    fn fill(t: &mut Tracked, unreadable: &mut u64) {
        if !t.peeked.is_empty() || t.done {
            return;
        }
        match t.file.new_entries(&mut t.pos, READ_AHEAD) {
            Ok(offsets) => {
                for o in offsets {
                    match t.file.entry(o) {
                        Ok(e) => t.peeked.push_back(e),
                        Err(_) => *unreadable += 1,
                    }
                }
            }
            Err(_) => *unreadable += 1,
        }
    }

    /// Reads what was written since the last poll, and hands over up to `POLL_ENTRIES` entries in journald's order, oldest first,
    /// each with how many numbers were missing before it: a gap, lines deleted on the host or not readable here.
    pub fn poll(&mut self) -> Vec<(Entry, u64)> {
        self.discover();
        // after the first look, a file that appears is a new one, read from its start
        self.start = None;
        self.at_tail = false;
        for t in self.files.values_mut() {
            if !t.done && t.peeked.is_empty() && t.file.refresh().is_err() {
                t.done = true;
            }
        }
        // the numbering of the newest journal last: an older seqnum_id's entries all came before
        let mut rank: HashMap<String, u64> = HashMap::new();
        for t in self.files.values() {
            let r = rank.entry(t.file.header.seqnum_id.clone()).or_insert(u64::MAX);
            *r = (*r).min(t.file.header.head_entry_realtime);
        }
        let mut out = Vec::new();
        while out.len() < POLL_ENTRIES {
            let mut unreadable = 0;
            for t in self.files.values_mut() {
                Self::fill(t, &mut unreadable);
            }
            self.unreadable += unreadable;
            let next = self.files.iter().filter_map(|(id, t)| t.peeked.front().map(|e| ((rank.get(&e.seqnum_id).copied().unwrap_or(0), e.seqnum), id.clone()))).min();
            let Some((_, id)) = next else { break };
            let e = self.files.get_mut(&id).unwrap().peeked.pop_front().unwrap();
            let last = self.last.get(&e.seqnum_id).copied();
            if last.is_some_and(|l| e.seqnum <= l) {
                continue; // the same entry in two files, or read twice: handed over once
            }
            let missing = last.map(|l| e.seqnum - l - 1).unwrap_or(0);
            if missing > 0 && self.held < HOLD_POLLS {
                // a file still being written with nothing more to read may get the missing entry in a moment
                let live_edge = self.files.values().any(|t| !t.done && t.file.header.state == 1 && t.file.header.seqnum_id == e.seqnum_id && t.peeked.is_empty());
                if live_edge {
                    self.held += 1;
                    self.files.get_mut(&id).unwrap().peeked.push_front(e);
                    break;
                }
            }
            self.held = 0;
            self.last.insert(e.seqnum_id.clone(), e.seqnum);
            out.push((e, missing));
        }
        // an archived file read to its end is let go; its file id stays known, so it is not read twice
        for t in self.files.values_mut() {
            if t.file.header.state == 2 && t.peeked.is_empty() {
                let mut probe = t.pos;
                if t.file.new_entries(&mut probe, 1).map(|o| o.is_empty()).unwrap_or(true) {
                    t.done = true;
                }
            }
        }
        out
    }

    pub fn files(&self) -> usize {
        self.files.len()
    }
}

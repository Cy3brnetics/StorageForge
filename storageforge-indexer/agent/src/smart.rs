//! What the disks plugin reads of a disk's health (roadmap section 11.4 and PF-04), decoded here from the bytes a disk answers, with
//! no smartctl in the agent's image.
//!
//! The readings are written in the shape `smartctl -j -a` prints, for the fields the controller reads (`health._smart` on its side):
//! the controller parses a disk's health from the agent with the same code it parses the SSH collector's report with, so the two
//! say the same of the same disk and can be compared.
//!
//! - ATA: the 512 bytes of SMART READ DATA and SMART READ THRESHOLDS, and SMART RETURN STATUS from the ATA registers in the sense
//!   data of an ATA PASS-THROUGH (16) command
//! - NVMe: the 512 bytes of the SMART / Health Information log page (02h)
//! - the kernel's own count of a disk's failed commands (`device/ioerr_cnt`), and the kernel's log lines that say a disk failed
//!
//! Every function here takes bytes or text and returns values: the ioctls are in the plugin's program.

use serde_json::{json, Map, Value};

/// The bytes of an ATA SMART data or thresholds sector.
pub const SECTOR: usize = 512;

/// The names smartctl gives the attributes the controller reads, and a few others worth showing.
fn attribute_name(id: u8) -> &'static str {
    match id {
        1 => "Raw_Read_Error_Rate",
        5 => "Reallocated_Sector_Ct",
        9 => "Power_On_Hours",
        10 => "Spin_Retry_Count",
        12 => "Power_Cycle_Count",
        187 => "Reported_Uncorrect",
        188 => "Command_Timeout",
        190 => "Airflow_Temperature_Cel",
        194 => "Temperature_Celsius",
        196 => "Reallocated_Event_Count",
        197 => "Current_Pending_Sector",
        198 => "Offline_Uncorrectable",
        199 => "UDMA_CRC_Error_Count",
        _ => "Unknown_Attribute",
    }
}

/// One attribute of the SMART data, with its threshold where the thresholds sector gave one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    pub id: u8,
    pub flags: u16,
    pub value: u8,
    pub worst: u8,
    pub raw: u64,
    pub thresh: Option<u8>,
}

fn checksum_ok(sector: &[u8]) -> bool {
    sector.len() == SECTOR && sector.iter().fold(0u8, |a, b| a.wrapping_add(*b)) == 0
}

/// The attributes of a SMART READ DATA sector, joined with the thresholds sector when there is one. None when the sector is not
/// one: the wrong size, or a checksum that does not add up (a bridge that answers with zeros, say).
pub fn ata_attributes(data: &[u8], thresholds: Option<&[u8]>) -> Option<Vec<Attribute>> {
    if !checksum_ok(data) {
        return None;
    }
    let thresholds = thresholds.filter(|t| checksum_ok(t));
    let mut out = Vec::new();
    for i in 0..30 {
        let e = &data[2 + i * 12..2 + i * 12 + 12];
        if e[0] == 0 {
            continue;
        }
        let raw = e[5..11].iter().rev().fold(0u64, |a, b| (a << 8) | u64::from(*b));
        let thresh = thresholds.and_then(|t| (0..30).map(|j| &t[2 + j * 12..2 + j * 12 + 12]).find(|x| x[0] == e[0]).map(|x| x[1]));
        out.push(Attribute { id: e[0], flags: u16::from_le_bytes([e[1], e[2]]), value: e[3], worst: e[4], raw, thresh });
    }
    Some(out)
}

/// What SMART RETURN STATUS said, from the sense data of the pass-through command (descriptor format, the ATA Status Return
/// descriptor): Some(true) passed, Some(false) a threshold is exceeded, None when the registers were not there to read.
pub fn ata_status(sense: &[u8]) -> Option<bool> {
    if sense.len() < 8 || sense[0] & 0x7f != 0x72 {
        return None;
    }
    let mut i = 8;
    let end = (8 + sense[7] as usize).min(sense.len());
    while i + 1 < end {
        let (code, len) = (sense[i], sense[i + 1] as usize);
        if code == 0x09 && len >= 12 && i + 14 <= sense.len() {
            let (mid, high) = (sense[i + 9], sense[i + 11]);
            return match (mid, high) {
                (0x4f, 0xc2) => Some(true),
                (0xf4, 0x2c) => Some(false),
                _ => None,
            };
        }
        i += 2 + len;
    }
    None
}

/// An ATA disk's health as smartctl's JSON writes it.
pub fn ata_json(attributes: &[Attribute], passed: Option<bool>) -> Value {
    let table: Vec<Value> = attributes
        .iter()
        .map(|a| {
            let mut v = json!({"id": a.id, "name": attribute_name(a.id), "value": a.value, "worst": a.worst, "flags": {"value": a.flags}, "raw": {"value": a.raw}});
            if let Some(t) = a.thresh {
                v["thresh"] = json!(t);
                v["when_failed"] = json!(if t > 0 && a.value <= t { "now" } else if t > 0 && a.worst <= t { "past" } else { "" });
            }
            v
        })
        .collect();
    let mut out = Map::new();
    out.insert("device".into(), json!({"protocol": "ATA"}));
    if let Some(p) = passed {
        out.insert("smart_status".into(), json!({"passed": p}));
    } else if attributes.iter().any(|a| a.thresh.is_some_and(|t| t > 0 && a.value <= t)) {
        // no status registers to read, and an attribute at or below its threshold: what smartctl would call failing
        out.insert("smart_status".into(), json!({"passed": false}));
    }
    out.insert("ata_smart_attributes".into(), json!({"revision": 16, "table": table}));
    let raw = |id: u8| attributes.iter().find(|a| a.id == id).map(|a| a.raw);
    if let Some(t) = raw(194).or_else(|| raw(190)) {
        out.insert("temperature".into(), json!({"current": t & 0xff}));
    }
    if let Some(h) = raw(9) {
        out.insert("power_on_time".into(), json!({"hours": h & 0xffff_ffff}));
    }
    Value::Object(out)
}

fn le(bytes: &[u8]) -> u128 {
    bytes.iter().rev().fold(0u128, |a, b| (a << 8) | u128::from(*b))
}

/// An NVMe disk's SMART / Health Information log (512 bytes) as smartctl's JSON writes it. None when it is not 512 bytes.
pub fn nvme_json(log: &[u8]) -> Option<Value> {
    if log.len() != SECTOR {
        return None;
    }
    // numbers of 128 bits, which smartctl writes as numbers too; past what JSON can carry exactly they are cut at u64
    let n = |a: usize| -> u64 { u64::try_from(le(&log[a..a + 16])).unwrap_or(u64::MAX) };
    let kelvin = u16::from_le_bytes([log[1], log[2]]);
    let celsius = i64::from(kelvin) - 273;
    let health = json!({
        "critical_warning": log[0],
        "temperature": celsius,
        "available_spare": log[3],
        "available_spare_threshold": log[4],
        "percentage_used": log[5],
        "data_units_read": n(32),
        "data_units_written": n(48),
        "host_reads": n(64),
        "host_writes": n(80),
        "controller_busy_time": n(96),
        "power_cycles": n(112),
        "power_on_hours": n(128),
        "unsafe_shutdowns": n(144),
        "media_errors": n(160),
        "num_err_log_entries": n(176),
    });
    Some(json!({
        "device": {"protocol": "NVMe"},
        "smart_status": {"passed": log[0] == 0, "nvme": {"value": log[0]}},
        "nvme_smart_health_information_log": health,
        "temperature": {"current": celsius},
        "power_on_time": {"hours": n(128)},
    }))
}

/// The kernel's count of a disk's commands that failed, from `device/ioerr_cnt` (written in hex, `0x1f`).
pub fn hex_count(text: &str) -> Option<u64> {
    let t = text.trim();
    u64::from_str_radix(t.strip_prefix("0x").unwrap_or(t), 16).ok()
}

/// Whether a kernel log line says a disk, its link or its array failed, and which disk it names if it names one. The words are the
/// kernel's own (the block layer, libata, the SCSI and NVMe drivers, md), matched without a regular expression.
pub fn disk_error(message: &str) -> Option<Option<String>> {
    let m = message.to_ascii_lowercase();
    const SAYS: [&str; 18] = [
        "i/o error", "medium error", "unrecovered read error", "critical medium error", "blk_update_request", "failed command:",
        "exception emask", "hard resetting link", "serror:", "controller is down", "i/o timeout", "resetting controller",
        "disk failure on", "auto-remapping", "sense key : medium", "read error", "write error", "uncorrectable",
    ];
    if !SAYS.iter().any(|s| m.contains(s)) {
        return None;
    }
    // the device named: "dev sda, sector", "[sdb]", "nvme0n1:", "ata3.00:"
    let words: Vec<&str> = message.split(|c: char| !(c.is_ascii_alphanumeric() || c == '.')).filter(|w| !w.is_empty()).collect();
    let dev = words.iter().find(|w| {
        let w = w.trim_end_matches('.');
        (w.starts_with("sd") && w.len() <= 5 && w[2..].bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()) && w.len() > 2)
            || (w.starts_with("nvme") && w[4..].bytes().all(|b| b.is_ascii_alphanumeric()) && w.len() > 4)
            || (w.starts_with("ata") && w.len() > 3 && w[3..].bytes().all(|b| b.is_ascii_digit() || b == b'.'))
            || (w.starts_with("vd") && w.len() == 3)
    });
    Some(dev.map(|d| d.trim_end_matches('.').to_string()))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A SMART data sector with these (id, value, worst, raw) attributes, its checksum made good.
    pub fn sector(attrs: &[(u8, u8, u8, u64)]) -> Vec<u8> {
        let mut s = vec![0u8; SECTOR];
        s[0] = 16;
        for (i, (id, value, worst, raw)) in attrs.iter().enumerate() {
            let e = &mut s[2 + i * 12..2 + i * 12 + 12];
            e[0] = *id;
            e[1] = 0x33;
            e[3] = *value;
            e[4] = *worst;
            e[5..11].copy_from_slice(&raw.to_le_bytes()[..6]);
        }
        let sum = s[..511].iter().fold(0u8, |a, b| a.wrapping_add(*b));
        s[511] = 0u8.wrapping_sub(sum);
        s
    }

    pub fn thresholds(attrs: &[(u8, u8)]) -> Vec<u8> {
        let mut s = vec![0u8; SECTOR];
        for (i, (id, t)) in attrs.iter().enumerate() {
            s[2 + i * 12] = *id;
            s[2 + i * 12 + 1] = *t;
        }
        let sum = s[..511].iter().fold(0u8, |a, b| a.wrapping_add(*b));
        s[511] = 0u8.wrapping_sub(sum);
        s
    }

    #[test]
    fn an_ata_disk_with_reallocated_sectors_reads_as_smartctl_writes_it() {
        let data = sector(&[(5, 90, 90, 8), (9, 100, 100, 12345), (194, 64, 50, 0x0012_0014_0024), (197, 100, 100, 2), (198, 100, 100, 1)]);
        let t = thresholds(&[(5, 36), (9, 0), (194, 0), (197, 0), (198, 0)]);
        let attrs = ata_attributes(&data, Some(&t)).unwrap();
        assert_eq!(attrs.len(), 5);
        assert_eq!(attrs[0], Attribute { id: 5, flags: 0x33, value: 90, worst: 90, raw: 8, thresh: Some(36) });
        let j = ata_json(&attrs, Some(true));
        assert_eq!(j["smart_status"]["passed"], true);
        assert_eq!(j["temperature"]["current"], 0x24);
        assert_eq!(j["power_on_time"]["hours"], 12345);
        assert_eq!(j["ata_smart_attributes"]["table"][3]["raw"]["value"], 2);
        assert_eq!(j["ata_smart_attributes"]["table"][0]["name"], "Reallocated_Sector_Ct");
        // a broken checksum is not a sector
        let mut bad = data.clone();
        bad[100] ^= 1;
        assert!(ata_attributes(&bad, None).is_none());
        assert!(ata_attributes(&data[..100], None).is_none());
        // with no status registers, an attribute at its threshold is a failing disk
        let failing = ata_attributes(&sector(&[(5, 30, 30, 900)]), Some(&thresholds(&[(5, 36)]))).unwrap();
        assert_eq!(ata_json(&failing, None)["smart_status"]["passed"], false);
        assert_eq!(ata_json(&failing, None)["ata_smart_attributes"]["table"][0]["when_failed"], "now");
    }

    #[test]
    fn the_status_registers_say_passed_or_failing() {
        let mut sense = vec![0u8; 32];
        sense[0] = 0x72;
        sense[7] = 14;
        sense[8] = 0x09;
        sense[9] = 12;
        sense[8 + 9] = 0x4f;
        sense[8 + 11] = 0xc2;
        assert_eq!(ata_status(&sense), Some(true));
        sense[8 + 9] = 0xf4;
        sense[8 + 11] = 0x2c;
        assert_eq!(ata_status(&sense), Some(false));
        sense[0] = 0x70;
        assert_eq!(ata_status(&sense), None, "fixed-format sense carries no registers");
        assert_eq!(ata_status(&[]), None);
    }

    #[test]
    fn an_nvme_log_reads_as_smartctl_writes_it() {
        let mut log = vec![0u8; SECTOR];
        log[0] = 0x04; // reliability degraded
        log[1..3].copy_from_slice(&313u16.to_le_bytes());
        log[3] = 100;
        log[4] = 10;
        log[5] = 3;
        log[128] = 0x10;
        log[129] = 0x27; // 10000 hours
        log[160] = 7; // media errors
        let j = nvme_json(&log).unwrap();
        assert_eq!(j["smart_status"]["passed"], false);
        assert_eq!(j["temperature"]["current"], 40);
        assert_eq!(j["power_on_time"]["hours"], 10000);
        assert_eq!(j["nvme_smart_health_information_log"]["media_errors"], 7);
        assert_eq!(j["nvme_smart_health_information_log"]["percentage_used"], 3);
        assert!(nvme_json(&log[..10]).is_none());
    }

    #[test]
    fn the_kernels_words_for_a_failing_disk_are_found_with_the_disk_they_name() {
        assert_eq!(disk_error("blk_update_request: I/O error, dev sdb, sector 123456 op 0x0:(READ)"), Some(Some("sdb".into())));
        assert_eq!(disk_error("ata3.00: failed command: READ FPDMA QUEUED"), Some(Some("ata3.00".into())));
        assert_eq!(disk_error("nvme nvme0: I/O 12 QID 3 timeout, aborting"), None);
        assert_eq!(disk_error("nvme0n1: I/O timeout"), Some(Some("nvme0n1".into())));
        assert_eq!(disk_error("sd 2:0:0:0: [sdc] tag#5 Sense Key : Medium Error [current]"), Some(Some("sdc".into())));
        assert_eq!(disk_error("md/raid1:md0: Disk failure on sda1, disabling device."), Some(Some("sda1".into())));
        assert_eq!(disk_error("EXT4-fs (sda1): mounted filesystem"), None);
        assert_eq!(disk_error("usb 1-1: new high-speed USB device"), None);
        assert_eq!(hex_count("0x1f\n"), Some(31));
        assert_eq!(hex_count("12"), Some(18));
        assert_eq!(hex_count("x"), None);
    }
}

//! Windows native service agent support (roadmap sections 11.1 and 11.4).
//!
//! On Windows, the agent is a native Windows service (`StorageForgeAgent`), never a container,
//! using the exact same plugin descriptor, SSH signature format, and signed manifest verification,
//! restricted to monitoring-only operations and managed over OpenSSH for Windows.
//! It also detects local shadow-copy tampering commands and shadow-copy disappearance for the
//! shadow-copy tripwire (`agentplugins` / `agentaction::wider`).

use crate::manifest::{self, Entry, Manifest};
use crate::plugin::{Anchors, Descriptor};
use crate::request;
use crate::sig::Signers;

pub const SERVICE_NAME: &str = "StorageForgeAgent";
pub const DISPLAY_NAME: &str = "StorageForge Monitoring Agent";
pub const AGENTCTL_USER: &str = "storageforge-agentctl";
pub const PROGRAM_DIR: &str = r"C:\Program Files\StorageForge\Agent";
pub const DATA_DIR: &str = r"C:\ProgramData\StorageForge\Agent";
pub const SSH_CONFIG_DIR: &str = r"C:\ProgramData\ssh";
pub const SSH_ADMIN_KEYS: &str = r"C:\ProgramData\ssh\administrators_authorized_keys";

/// Non-container host agent execution mode on Windows.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    MonitoringOnly,
}

/// Native Windows service configuration validated before install or startup.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ServiceConfig {
    pub service_name: String,
    pub program_dir: String,
    pub data_dir: String,
    pub arch: String,
    pub mode: Mode,
    pub managed_over: &'static str,
    pub container_runtime: Option<String>,
}

impl ServiceConfig {
    pub fn monitoring(arch: &str) -> Self {
        Self {
            service_name: SERVICE_NAME.to_string(),
            program_dir: PROGRAM_DIR.to_string(),
            data_dir: DATA_DIR.to_string(),
            arch: arch.to_string(),
            mode: Mode::MonitoringOnly,
            managed_over: "openssh-windows",
            container_runtime: None,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.container_runtime.is_some() {
            return Err("the Windows agent runs as a native service, never a container".into());
        }
        if self.mode != Mode::MonitoringOnly {
            return Err("the Windows agent supports monitoring-only mode".into());
        }
        if !is_safe_service_name(&self.service_name) {
            return Err("invalid Windows service name".into());
        }
        if self.arch != "x86_64" && self.arch != "aarch64" {
            return Err("architecture must be x86_64 or aarch64".into());
        }
        validate_windows_local_path(&self.program_dir)?;
        validate_windows_local_path(&self.data_dir)?;
        Ok(())
    }

    /// Whether an operation requested over OpenSSH for Windows is permitted on a monitoring-only Windows host.
    pub fn allows_operation(&self, op: &str) -> bool {
        request::OPS.contains(&op)
    }
}

pub fn is_safe_service_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

pub fn validate_windows_local_path(path: &str) -> Result<(), String> {
    if path.len() < 4 || path.len() > 260 {
        return Err("Windows path length out of range".into());
    }
    let bytes = path.as_bytes();
    if !bytes[0].is_ascii_alphabetic() || bytes[1] != b':' || bytes[2] != b'\\' {
        return Err("must be a local drive path such as C:\\ProgramData\\...".into());
    }
    if path.starts_with(r"\\") || path.contains("..") {
        return Err("UNC and traversal paths are refused".into());
    }
    if bytes.iter().any(|b| *b < 0x20 || b"\"<>|*?;&$`".contains(b)) {
        return Err("path contains disallowed characters".into());
    }
    Ok(())
}

/// Validates a manifest for the native Windows service using the exact same signed manifest rules.
pub fn verify_manifest(bytes: &[u8], signature: &str, controller: &Signers) -> Result<Manifest, String> {
    manifest::verify(bytes, signature, controller)
}

/// Validates a signed plugin descriptor against its manifest entry using the shared plugin format.
pub fn verify_plugin(
    entry: &Entry,
    descriptor_bytes: &[u8],
    descriptor_sig: &str,
    anchors: &Anchors,
) -> Result<Descriptor, String> {
    Manifest::admit_plugin(entry, descriptor_bytes, descriptor_sig, anchors)
}

/// OpenSSH for Windows `sshd_config` fragment restricting `storageforge-agentctl` to the agent controller executable.
pub fn openssh_match_block(agentctl_exe: &str) -> Result<String, String> {
    validate_windows_local_path(agentctl_exe)?;
    Ok(format!(
        "Match User {AGENTCTL_USER}\n    ForceCommand \"{agentctl_exe}\" --stdio\n    AllowTcpForwarding no\n    AllowAgentForwarding no\n    PermitTTY no\n    X11Forwarding no\n"
    ))
}

/// Windows service registration arguments (`sc.exe create`) running under hardened `NT AUTHORITY\\LocalSystem` service context.
pub fn service_create_args(agent_exe: &str, data_dir: &str) -> Result<Vec<String>, String> {
    validate_windows_local_path(agent_exe)?;
    validate_windows_local_path(data_dir)?;
    Ok(vec![
        "create".into(),
        SERVICE_NAME.into(),
        format!("binPath= \"{agent_exe}\" run --etc \"{data_dir}\\etc\" --manifest \"{data_dir}\\manifest\" --state \"{data_dir}\\state\""),
        "start= auto".into(),
        format!("DisplayName= {DISPLAY_NAME}"),
    ])
}

/// `icacls` invocations keeping `DATA_DIR` private to SYSTEM and Administrators (read/write denied to Users).
pub fn acl_lockdown_args(data_dir: &str) -> Result<Vec<String>, String> {
    validate_windows_local_path(data_dir)?;
    Ok(vec![
        data_dir.into(),
        "/inheritance:r".into(),
        "/grant:r".into(),
        "SYSTEM:(OI)(CI)F".into(),
        "Administrators:(OI)(CI)F".into(),
    ])
}

/// Kinds of Windows shadow-copy tampering detected for the tripwire plugin.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TripwireRule {
    VssadminDeleteShadows,
    WmicShadowcopyDelete,
    PowershellWin32ShadowCopy,
    WbadminDeleteCatalog,
    BcdeditRecoveryDisabled,
    ShadowsVanished,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TripwireMatch {
    pub rule: TripwireRule,
    pub detail: String,
}

fn has_all_tokens(haystack_lower: &str, groups: &[&[&str]]) -> bool {
    groups
        .iter()
        .all(|alts| alts.iter().any(|tok| haystack_lower.contains(tok)))
}

/// Matches process command lines (from Windows Security 4688 auditing or Sysmon Event ID 1) that delete or disable shadow copies.
/// The agent detects and reports these; it does not act as an inline process-blocking EDR.
pub fn detect_shadow_copy_tamper(command_line: &str) -> Option<TripwireMatch> {
    let normalized = command_line
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase();
    if normalized.is_empty() || normalized.len() > 8192 {
        return None;
    }
    if has_all_tokens(&normalized, &[&["vssadmin", "vssadmin.exe"], &["delete"], &["shadows"]]) {
        return Some(TripwireMatch {
            rule: TripwireRule::VssadminDeleteShadows,
            detail: "vssadmin delete shadows".into(),
        });
    }
    if has_all_tokens(&normalized, &[&["wmic", "wmic.exe"], &["shadowcopy"], &["delete"]]) {
        return Some(TripwireMatch {
            rule: TripwireRule::WmicShadowcopyDelete,
            detail: "wmic shadowcopy delete".into(),
        });
    }
    if has_all_tokens(
        &normalized,
        &[
            &["win32_shadowcopy"],
            &["delete", "remove-ciminstance", "remove-wmiobject"],
        ],
    ) {
        return Some(TripwireMatch {
            rule: TripwireRule::PowershellWin32ShadowCopy,
            detail: "PowerShell Win32_ShadowCopy removal".into(),
        });
    }
    if has_all_tokens(
        &normalized,
        &[&["wbadmin", "wbadmin.exe"], &["delete"], &["catalog", "systemstatebackup"]],
    ) {
        return Some(TripwireMatch {
            rule: TripwireRule::WbadminDeleteCatalog,
            detail: "wbadmin delete catalog".into(),
        });
    }
    if has_all_tokens(
        &normalized,
        &[&["bcdedit", "bcdedit.exe"], &["recoveryenabled"], &["no", "off", "0"]],
    ) {
        return Some(TripwireMatch {
            rule: TripwireRule::BcdeditRecoveryDisabled,
            detail: "bcdedit recoveryenabled no".into(),
        });
    }
    None
}

/// Reports when a Windows host's shadow copy count drops unexpectedly between polls.
pub fn check_shadow_count(previous: u32, current: u32) -> Option<TripwireMatch> {
    if current < previous {
        Some(TripwireMatch {
            rule: TripwireRule::ShadowsVanished,
            detail: format!("shadow copies dropped from {previous} to {current}"),
        })
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::tests as mtests;
    use crate::needs::Needs;
    use crate::plugin::tests::{anchors, descriptor};
    use crate::sig;
    use ed25519_dalek::SigningKey;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    #[test]
    fn monitoring_service_enforces_native_non_container_and_ops() {
        let mut cfg = ServiceConfig::monitoring("x86_64");
        assert!(cfg.validate().is_ok());
        assert!(cfg.allows_operation("status"));
        assert!(cfg.allows_operation("wipe"));
        assert!(!cfg.allows_operation("deploy"));
        assert!(!cfg.allows_operation("quarantine"));

        cfg.container_runtime = Some("docker".into());
        assert!(cfg.validate().is_err());

        cfg.container_runtime = None;
        cfg.data_dir = r"\\evil\share\agent".into();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn windows_uses_identical_manifest_and_plugin_signatures() {
        let (release, operator, controller, agent) = (key(1), key(2), key(3), key(4));
        let a = anchors(&release, &operator, &controller);

        let prog = b"MZ-native-windows-plugin";
        let desc = descriptor("shadow-tripwire", prog, "{}");
        let desc_sig = sig::sign(&release, sig::NS_PLUGIN, &desc);
        let desc_hash = sig::sha256_hex(&desc);

        let plugin_entry = format!(
            r#"{{"name":"shadow-tripwire","descriptor":"{desc_hash}","signer":"release","needs":{{}}}}"#
        );
        let m_bytes = mtests::manifest(&agent, 1, 1000, &plugin_entry);
        let m_sig = sig::sign(&controller, sig::NS_MANIFEST, &m_bytes);

        let manifest = verify_manifest(&m_bytes, &m_sig, &a.controller).unwrap();
        assert_eq!(manifest.plugins.len(), 1);
        assert_eq!(manifest.plugins[0].needs, Needs::default());

        let verified = verify_plugin(&manifest.plugins[0], &desc, &desc_sig, &a).unwrap();
        assert_eq!(verified.name, "shadow-tripwire");
    }

    #[test]
    fn openssh_and_sc_commands_reject_unsafe_paths() {
        let block = openssh_match_block(r"C:\Program Files\StorageForge\Agent\storageforge-agentctl.exe").unwrap();
        assert!(block.contains("Match User storageforge-agentctl"));
        assert!(block.contains("AllowTcpForwarding no"));
        assert!(openssh_match_block(r"C:\bad;whoami.exe").is_err());

        let sc = service_create_args(
            r"C:\Program Files\StorageForge\Agent\storageforge-agent.exe",
            DATA_DIR,
        )
        .unwrap();
        assert_eq!(sc[0], "create");
        assert_eq!(sc[1], SERVICE_NAME);

        let acl = acl_lockdown_args(DATA_DIR).unwrap();
        assert!(acl.contains(&"SYSTEM:(OI)(CI)F".to_string()));
    }

    #[test]
    fn shadow_copy_tripwire_detects_all_documented_patterns() {
        let cases = [
            ("vssadmin.exe delete shadows /all /quiet", TripwireRule::VssadminDeleteShadows),
            ("cmd /c wmic shadowcopy delete /nointeractive", TripwireRule::WmicShadowcopyDelete),
            (
                "powershell -Command \"Get-CimInstance Win32_ShadowCopy | Remove-CimInstance\"",
                TripwireRule::PowershellWin32ShadowCopy,
            ),
            ("wbadmin DELETE catalog -quiet", TripwireRule::WbadminDeleteCatalog),
            ("bcdedit /set {default} recoveryenabled No", TripwireRule::BcdeditRecoveryDisabled),
        ];
        for (cmd, expected) in cases {
            let hit = detect_shadow_copy_tamper(cmd).expect(cmd);
            assert_eq!(hit.rule, expected);
        }
        assert!(detect_shadow_copy_tamper("vssadmin list shadows").is_none());
        assert!(detect_shadow_copy_tamper("powershell Get-Process").is_none());
        assert_eq!(
            check_shadow_count(4, 1).unwrap().rule,
            TripwireRule::ShadowsVanished
        );
        assert!(check_shadow_count(4, 4).is_none());
    }
}

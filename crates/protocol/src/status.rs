use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum AgentMessage {

    Hello {
        agent_version: String,
        protocol_version: u32,
    },
    Heartbeat(AgentStatus),
    Ack { id: u64 },
    Error {
        id: Option<u64>,
        code: ErrorCode,
        message: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    InvalidMessage,
    InvalidConfig,
    InvalidBpfFilter,
    InvalidState,
    InterfaceNotFound,
    DiskFull,
    Internal,
}



#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionState {
    Idle,
    Configured,
    Running,
    Finished,
    Interrupted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentStatus {
    pub state: MissionState,
    pub mission_id: Option<String>,
    pub mission_duration_secs: Option<u64>,
    pub packets_per_sec: u64,
    pub span_traffic_detected: bool,
    pub packets_dropped: u64,
    pub disk_free_bytes: u64,
    pub pcap_active: bool,
    pub segments_written: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ack_as_expected() {
        let json = serde_json::to_string(&AgentMessage::Ack { id: 7 }).unwrap();
        assert_eq!(json, r#"{"type":"ack","id":7}"#);
    }

    #[test]
    fn message_without_id() {
        let msg = AgentMessage::Error {
            id: None,
            code: ErrorCode::InvalidMessage,
            message: "message illisible".into(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(
            json,
            r#"{"type":"error","id":null,"code":"invalid_message","message":"message illisible"}"#
        );
    }

    #[test]
    fn back_and_forth_between_server_and_client() {
        for msg in [
            AgentMessage::Hello {
                agent_version: "0.1.0".into(),
                protocol_version: crate::PROTOCOL_VERSION,
            },
            AgentMessage::Ack { id: 3 },
            AgentMessage::Error {
                id: Some(4),
                code: ErrorCode::InvalidState,
                message: "start reçu sans configuration".into(),
            },
        ] {
            let json = serde_json::to_string(&msg).unwrap();
            let relu: AgentMessage = serde_json::from_str(&json).unwrap();
            assert_eq!(relu, msg);
        }
    }

    fn status_ongoing() -> AgentStatus {
        AgentStatus {
            state: MissionState::Running,
            mission_id: Some("m-01".into()),
            mission_duration_secs: Some(3600),
            packets_per_sec: 1200,
            span_traffic_detected: true,
            packets_dropped: 0,
            disk_free_bytes: 400_000_000_000,
            pcap_active: false,
            segments_written: 6,
        }
    }

    #[test]
    fn heartbeat_conform() {
        let msg = AgentMessage::Heartbeat(status_ongoing());
        let value = serde_json::to_value(&msg).unwrap();
        assert_eq!(
            value,
            serde_json::json!({
                "type": "heartbeat",
                "state": "running",
                "mission_id": "m-01",
                "mission_duration_secs": 3600,
                "packets_per_sec": 1200,
                "span_traffic_detected": true,
                "packets_dropped": 0,
                "disk_free_bytes": 400_000_000_000u64,
                "pcap_active": false,
                "segments_written": 6
            })
        );
    }

    #[test]
    fn heartbeat_missing_mission() {
        let msg = AgentMessage::Heartbeat(AgentStatus {
            state: MissionState::Idle,
            mission_id: None,
            mission_duration_secs: None,
            ..status_ongoing()
        });
        let value = serde_json::to_value(&msg).unwrap();
        assert_eq!(value["state"], "idle");
        assert!(value["mission_id"].is_null());

        let relu: AgentMessage = serde_json::from_value(value).unwrap();
        assert_eq!(relu, msg);
    }
}
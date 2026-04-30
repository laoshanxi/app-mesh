// subscribe_test.rs
//
// Unit tests for event subscription message types.
// These tests verify serialization/deserialization and event model correctness
// without requiring a running server.

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};
    use serde_json::json;
    use std::collections::HashMap;

    const EVENT_URI: &str = "/appmesh/event";

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct AppEvent {
        subscription_id: String,
        event_type: String,
        app_name: String,
        timestamp: i64,
        sequence: u64,
        data: serde_json::Value,
    }

    #[test]
    fn test_app_event_deserialization() {
        let raw = r#"{
            "subscription_id": "sub123",
            "event_type": "EXIT",
            "app_name": "myapp",
            "timestamp": 1714000000,
            "sequence": 42,
            "data": {"exit_code": 1, "pid": 12345}
        }"#;

        let event: AppEvent = serde_json::from_str(raw).expect("Failed to deserialize AppEvent");
        assert_eq!(event.subscription_id, "sub123");
        assert_eq!(event.event_type, "EXIT");
        assert_eq!(event.app_name, "myapp");
        assert_eq!(event.timestamp, 1714000000);
        assert_eq!(event.sequence, 42);
        assert_eq!(event.data["exit_code"], 1);
        assert_eq!(event.data["pid"], 12345);
    }

    #[test]
    fn test_app_event_serialization_roundtrip() {
        let event = AppEvent {
            subscription_id: "sub-rt".to_string(),
            event_type: "START".to_string(),
            app_name: "test-app".to_string(),
            timestamp: 1714000000,
            sequence: 1,
            data: json!({"pid": 9999, "process_uuid": "abc-def"}),
        };

        let serialized = serde_json::to_string(&event).expect("Failed to serialize");
        let deserialized: AppEvent = serde_json::from_str(&serialized).expect("Failed to deserialize");
        assert_eq!(event, deserialized);
    }

    #[test]
    fn test_event_uri_identification() {
        assert_eq!(EVENT_URI, "/appmesh/event");

        // An event response is identified by request_uri == EVENT_URI
        let response_uri = "/appmesh/event";
        assert!(response_uri == EVENT_URI, "Event responses use the EVENT_URI sentinel");

        let normal_uri = "/appmesh/app/test";
        assert!(normal_uri != EVENT_URI, "Normal responses should not match EVENT_URI");
    }

    #[test]
    fn test_event_types() {
        let valid_types = vec![
            "START",
            "EXIT",
            "STDOUT",
            "HEALTH",
            "STATUS",
            "REMOVED",
        ];

        for event_type in &valid_types {
            let event = AppEvent {
                subscription_id: "sub-1".to_string(),
                event_type: event_type.to_string(),
                app_name: "test".to_string(),
                timestamp: 0,
                sequence: 0,
                data: json!({}),
            };
            let json_str = serde_json::to_string(&event).expect("serialize");
            assert!(json_str.contains(event_type));
        }
    }

    #[test]
    fn test_event_with_headers() {
        let mut headers: HashMap<String, String> = HashMap::new();
        headers.insert("X-Subscription-Id".to_string(), "sub-hdr".to_string());
        headers.insert("X-Event-Type".to_string(), "EXIT".to_string());
        headers.insert("X-App-Name".to_string(), "myapp".to_string());

        assert_eq!(headers.get("X-Subscription-Id"), Some(&"sub-hdr".to_string()));
        assert_eq!(headers.get("X-Event-Type"), Some(&"EXIT".to_string()));
        assert_eq!(headers.get("X-App-Name"), Some(&"myapp".to_string()));
    }

    #[test]
    fn test_subscribe_result_deserialization() {
        let raw = r#"{
            "subscription_id": "cqk8g7l4d",
            "app_name": "myapp",
            "events": ["START", "EXIT", "STDOUT"]
        }"#;

        #[derive(Debug, Deserialize)]
        struct SubscriptionResult {
            subscription_id: String,
            app_name: String,
            events: Vec<String>,
        }

        let result: SubscriptionResult = serde_json::from_str(raw).expect("Failed to deserialize");
        assert_eq!(result.subscription_id, "cqk8g7l4d");
        assert_eq!(result.app_name, "myapp");
        assert_eq!(result.events.len(), 3);
        assert!(result.events.contains(&"STDOUT".to_string()));
    }
}

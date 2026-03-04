use bifrost_app::runtime::{AppConfig, QueueOverflowPolicyConfig};
use bifrost_bridge::{
    DEFAULT_COMMAND_QUEUE_CAPACITY, DEFAULT_INBOUND_DEDUPE_CACHE_LIMIT,
    DEFAULT_INBOUND_QUEUE_CAPACITY, DEFAULT_OUTBOUND_QUEUE_CAPACITY,
};

#[test]
fn app_config_defaults_bridge_queue_options() {
    let raw = serde_json::json!({
        "group_path": "./group.json",
        "share_path": "./share.json",
        "state_path": "./state.json",
        "relays": ["ws://127.0.0.1:8194"],
        "peers": []
    });
    let cfg: AppConfig = serde_json::from_value(raw).expect("parse config");

    assert_eq!(
        cfg.options.bridge_command_queue_capacity,
        DEFAULT_COMMAND_QUEUE_CAPACITY
    );
    assert_eq!(
        cfg.options.bridge_inbound_queue_capacity,
        DEFAULT_INBOUND_QUEUE_CAPACITY
    );
    assert_eq!(
        cfg.options.bridge_outbound_queue_capacity,
        DEFAULT_OUTBOUND_QUEUE_CAPACITY
    );
    assert!(matches!(
        cfg.options.bridge_command_overflow_policy,
        QueueOverflowPolicyConfig::Fail
    ));
    assert!(matches!(
        cfg.options.bridge_inbound_overflow_policy,
        QueueOverflowPolicyConfig::DropOldest
    ));
    assert!(matches!(
        cfg.options.bridge_outbound_overflow_policy,
        QueueOverflowPolicyConfig::Fail
    ));
    assert_eq!(
        cfg.options.bridge_inbound_dedupe_cache_limit,
        DEFAULT_INBOUND_DEDUPE_CACHE_LIMIT
    );
    assert_eq!(cfg.options.max_future_skew_secs, 30);
}

#[test]
fn app_config_parses_explicit_bridge_queue_options() {
    let raw = serde_json::json!({
        "group_path": "./group.json",
        "share_path": "./share.json",
        "state_path": "./state.json",
        "relays": ["ws://127.0.0.1:8194"],
        "peers": [],
        "options": {
            "max_future_skew_secs": 45,
            "bridge_command_queue_capacity": 32,
            "bridge_inbound_queue_capacity": 256,
            "bridge_outbound_queue_capacity": 64,
            "bridge_command_overflow_policy": "drop_oldest",
            "bridge_inbound_overflow_policy": "fail",
            "bridge_outbound_overflow_policy": "drop_oldest",
            "bridge_inbound_dedupe_cache_limit": 2048
        }
    });
    let cfg: AppConfig = serde_json::from_value(raw).expect("parse config");

    assert_eq!(cfg.options.bridge_command_queue_capacity, 32);
    assert_eq!(cfg.options.bridge_inbound_queue_capacity, 256);
    assert_eq!(cfg.options.bridge_outbound_queue_capacity, 64);
    assert!(matches!(
        cfg.options.bridge_command_overflow_policy,
        QueueOverflowPolicyConfig::DropOldest
    ));
    assert!(matches!(
        cfg.options.bridge_inbound_overflow_policy,
        QueueOverflowPolicyConfig::Fail
    ));
    assert!(matches!(
        cfg.options.bridge_outbound_overflow_policy,
        QueueOverflowPolicyConfig::DropOldest
    ));
    assert_eq!(cfg.options.bridge_inbound_dedupe_cache_limit, 2048);
    assert_eq!(cfg.options.max_future_skew_secs, 45);
}

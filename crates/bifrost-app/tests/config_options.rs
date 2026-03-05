use bifrost_app::runtime::{AppConfig, QueueOverflowPolicyConfig};
use bifrost_bridge_tokio::{
    DEFAULT_COMMAND_QUEUE_CAPACITY, DEFAULT_INBOUND_DEDUPE_CACHE_LIMIT,
    DEFAULT_INBOUND_QUEUE_CAPACITY, DEFAULT_OUTBOUND_QUEUE_CAPACITY,
};

#[test]
fn app_config_defaults_router_queue_options() {
    let raw = serde_json::json!({
        "group_path": "./group.json",
        "share_path": "./share.json",
        "state_path": "./state.json",
        "relays": ["ws://127.0.0.1:8194"],
        "peers": []
    });
    let cfg: AppConfig = serde_json::from_value(raw).expect("parse config");

    assert_eq!(
        cfg.options.router_command_queue_capacity,
        DEFAULT_COMMAND_QUEUE_CAPACITY
    );
    assert_eq!(
        cfg.options.router_inbound_queue_capacity,
        DEFAULT_INBOUND_QUEUE_CAPACITY
    );
    assert_eq!(
        cfg.options.router_outbound_queue_capacity,
        DEFAULT_OUTBOUND_QUEUE_CAPACITY
    );
    assert!(matches!(
        cfg.options.router_command_overflow_policy,
        QueueOverflowPolicyConfig::Fail
    ));
    assert!(matches!(
        cfg.options.router_inbound_overflow_policy,
        QueueOverflowPolicyConfig::DropOldest
    ));
    assert!(matches!(
        cfg.options.router_outbound_overflow_policy,
        QueueOverflowPolicyConfig::Fail
    ));
    assert_eq!(
        cfg.options.router_inbound_dedupe_cache_limit,
        DEFAULT_INBOUND_DEDUPE_CACHE_LIMIT
    );
    assert_eq!(cfg.options.max_future_skew_secs, 30);
}

#[test]
fn app_config_parses_explicit_router_queue_options() {
    let raw = serde_json::json!({
        "group_path": "./group.json",
        "share_path": "./share.json",
        "state_path": "./state.json",
        "relays": ["ws://127.0.0.1:8194"],
        "peers": [],
        "options": {
            "max_future_skew_secs": 45,
            "router_command_queue_capacity": 32,
            "router_inbound_queue_capacity": 256,
            "router_outbound_queue_capacity": 64,
            "router_command_overflow_policy": "drop_oldest",
            "router_inbound_overflow_policy": "fail",
            "router_outbound_overflow_policy": "drop_oldest",
            "router_inbound_dedupe_cache_limit": 2048
        }
    });
    let cfg: AppConfig = serde_json::from_value(raw).expect("parse config");

    assert_eq!(cfg.options.router_command_queue_capacity, 32);
    assert_eq!(cfg.options.router_inbound_queue_capacity, 256);
    assert_eq!(cfg.options.router_outbound_queue_capacity, 64);
    assert!(matches!(
        cfg.options.router_command_overflow_policy,
        QueueOverflowPolicyConfig::DropOldest
    ));
    assert!(matches!(
        cfg.options.router_inbound_overflow_policy,
        QueueOverflowPolicyConfig::Fail
    ));
    assert!(matches!(
        cfg.options.router_outbound_overflow_policy,
        QueueOverflowPolicyConfig::DropOldest
    ));
    assert_eq!(cfg.options.router_inbound_dedupe_cache_limit, 2048);
    assert_eq!(cfg.options.max_future_skew_secs, 45);
}

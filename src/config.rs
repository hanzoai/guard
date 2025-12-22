//! Configuration for Hanzo Guard

use serde::{Deserialize, Serialize};

/// Main configuration for Guard
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GuardConfig {
    /// PII detection configuration
    pub pii: PiiConfig,
    /// Injection detection configuration
    pub injection: InjectionConfig,
    /// Content filter configuration
    pub content_filter: ContentFilterConfig,
    /// Rate limiting configuration
    pub rate_limit: RateLimitConfig,
    /// Audit configuration
    pub audit: AuditConfig,
}

impl GuardConfig {
    /// Create a new config with all features enabled
    pub fn full() -> Self {
        Self {
            pii: PiiConfig {
                enabled: true,
                ..Default::default()
            },
            injection: InjectionConfig {
                enabled: true,
                ..Default::default()
            },
            content_filter: ContentFilterConfig {
                enabled: true,
                ..Default::default()
            },
            rate_limit: RateLimitConfig {
                enabled: true,
                ..Default::default()
            },
            audit: AuditConfig {
                enabled: true,
                ..Default::default()
            },
        }
    }

    /// Create a minimal config (PII only)
    pub fn minimal() -> Self {
        Self {
            pii: PiiConfig {
                enabled: true,
                ..Default::default()
            },
            injection: InjectionConfig {
                enabled: false,
                ..Default::default()
            },
            content_filter: ContentFilterConfig {
                enabled: false,
                ..Default::default()
            },
            rate_limit: RateLimitConfig {
                enabled: false,
                ..Default::default()
            },
            audit: AuditConfig {
                enabled: false,
                ..Default::default()
            },
        }
    }
}

/// PII detection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PiiConfig {
    /// Enable PII detection
    pub enabled: bool,
    /// Detect SSNs
    pub detect_ssn: bool,
    /// Detect credit cards
    pub detect_credit_card: bool,
    /// Detect emails
    pub detect_email: bool,
    /// Detect phone numbers
    pub detect_phone: bool,
    /// Detect IP addresses
    pub detect_ip: bool,
    /// Detect API keys/secrets
    pub detect_api_keys: bool,
    /// Redaction placeholder format (use {TYPE} for type name)
    pub redaction_format: String,
}

impl Default for PiiConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            detect_ssn: true,
            detect_credit_card: true,
            detect_email: true,
            detect_phone: true,
            detect_ip: true,
            detect_api_keys: true,
            redaction_format: "[REDACTED:{TYPE}]".to_string(),
        }
    }
}

/// Injection detection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectionConfig {
    /// Enable injection detection
    pub enabled: bool,
    /// Block on detection (vs. just warn)
    pub block_on_detection: bool,
    /// Sensitivity level (0.0-1.0)
    pub sensitivity: f32,
    /// Custom patterns to detect
    pub custom_patterns: Vec<String>,
}

impl Default for InjectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            block_on_detection: true,
            sensitivity: 0.7,
            custom_patterns: vec![],
        }
    }
}

/// Content filter configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentFilterConfig {
    /// Enable content filtering
    pub enabled: bool,
    /// Zen Guard API endpoint
    pub api_endpoint: String,
    /// API key for Zen Guard
    pub api_key: Option<String>,
    /// Block controversial content (not just unsafe)
    pub block_controversial: bool,
    /// Categories to block
    pub blocked_categories: Vec<String>,
    /// Timeout in milliseconds
    pub timeout_ms: u64,
}

impl Default for ContentFilterConfig {
    fn default() -> Self {
        Self {
            enabled: false, // Disabled by default as it requires API
            api_endpoint: "https://api.zenlm.ai/v1/guard".to_string(),
            api_key: None,
            block_controversial: false,
            blocked_categories: vec![
                "Violent".to_string(),
                "IllegalActs".to_string(),
                "SexualContent".to_string(),
                "SelfHarm".to_string(),
                "Jailbreak".to_string(),
            ],
            timeout_ms: 5000,
        }
    }
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Enable rate limiting
    pub enabled: bool,
    /// Requests per minute per user
    pub requests_per_minute: u32,
    /// Tokens per minute per user
    pub tokens_per_minute: u32,
    /// Burst allowance
    pub burst_size: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            requests_per_minute: 60,
            tokens_per_minute: 100_000,
            burst_size: 10,
        }
    }
}

/// Audit logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    /// Enable audit logging
    pub enabled: bool,
    /// Log full content (vs. just hashes)
    pub log_content: bool,
    /// Log to stdout
    pub log_stdout: bool,
    /// Log file path
    pub log_file: Option<String>,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            log_content: false, // Privacy by default
            log_stdout: false,
            log_file: None,
        }
    }
}

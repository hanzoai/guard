//! Error types for Hanzo Guard

use thiserror::Error;

/// Result type alias for Guard operations
pub type Result<T> = std::result::Result<T, GuardError>;

/// Guard error types
#[derive(Debug, Error)]
pub enum GuardError {
    /// Content was blocked due to safety policy
    #[error("Content blocked: {reason} (category: {category:?})")]
    ContentBlocked {
        reason: String,
        category: SafetyCategory,
    },

    /// Rate limit exceeded
    #[error("Rate limit exceeded: {0}")]
    RateLimitExceeded(String),

    /// PII detection error
    #[error("PII detection error: {0}")]
    PiiDetectionError(String),

    /// Injection detection error
    #[error("Injection detection error: {0}")]
    InjectionDetectionError(String),

    /// Content filter API error
    #[error("Content filter error: {0}")]
    ContentFilterError(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    ConfigError(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    /// IO error
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    /// HTTP error (when content filter is enabled)
    #[cfg(feature = "content-filter")]
    #[error("HTTP error: {0}")]
    HttpError(#[from] reqwest::Error),
}

/// Safety categories aligned with Zen Guard
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum SafetyCategory {
    /// Violence and weapons
    Violent,
    /// Non-violent illegal activities
    IllegalActs,
    /// Sexual content
    SexualContent,
    /// Personally identifiable information
    Pii,
    /// Self-harm and suicide
    SelfHarm,
    /// Discrimination and hate speech
    UnethicalActs,
    /// Political misinformation
    PoliticallySensitive,
    /// Copyright infringement
    CopyrightViolation,
    /// Jailbreak attempts
    Jailbreak,
    /// No specific category
    None,
}

impl std::fmt::Display for SafetyCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SafetyCategory::Violent => write!(f, "Violent"),
            SafetyCategory::IllegalActs => write!(f, "Non-violent Illegal Acts"),
            SafetyCategory::SexualContent => write!(f, "Sexual Content"),
            SafetyCategory::Pii => write!(f, "PII"),
            SafetyCategory::SelfHarm => write!(f, "Suicide & Self-Harm"),
            SafetyCategory::UnethicalActs => write!(f, "Unethical Acts"),
            SafetyCategory::PoliticallySensitive => write!(f, "Politically Sensitive"),
            SafetyCategory::CopyrightViolation => write!(f, "Copyright Violation"),
            SafetyCategory::Jailbreak => write!(f, "Jailbreak"),
            SafetyCategory::None => write!(f, "None"),
        }
    }
}

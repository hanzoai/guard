//! Core types for Hanzo Guard

use crate::error::SafetyCategory;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Result of sanitizing input or output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SanitizeResult {
    /// Content is clean, no modifications needed
    Clean(String),

    /// Content was redacted (PII removed, etc.)
    Redacted {
        /// The sanitized text with redactions
        text: String,
        /// List of redactions made
        redactions: Vec<Redaction>,
    },

    /// Content was blocked entirely
    Blocked {
        /// Reason for blocking
        reason: String,
        /// Safety category that triggered the block
        category: SafetyCategory,
    },
}

impl SanitizeResult {
    /// Get the sanitized text if available
    pub fn text(&self) -> Option<&str> {
        match self {
            SanitizeResult::Clean(text) => Some(text),
            SanitizeResult::Redacted { text, .. } => Some(text),
            SanitizeResult::Blocked { .. } => None,
        }
    }

    /// Check if content was blocked
    pub fn is_blocked(&self) -> bool {
        matches!(self, SanitizeResult::Blocked { .. })
    }

    /// Check if content was modified
    pub fn is_modified(&self) -> bool {
        matches!(self, SanitizeResult::Redacted { .. })
    }
}

/// A redaction made to content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Redaction {
    /// Type of redaction
    pub redaction_type: RedactionType,
    /// Original value (for audit purposes, may be hashed)
    pub original_hash: String,
    /// Replacement text used
    pub replacement: String,
    /// Start position in original text
    pub start: usize,
    /// End position in original text
    pub end: usize,
}

/// Types of redactions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RedactionType {
    /// Social Security Number
    Ssn,
    /// Credit Card Number
    CreditCard,
    /// Email Address
    Email,
    /// Phone Number
    Phone,
    /// IP Address
    IpAddress,
    /// API Key or Secret
    ApiKey,
    /// Password
    Password,
    /// Other PII
    OtherPii,
}

impl std::fmt::Display for RedactionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RedactionType::Ssn => write!(f, "SSN"),
            RedactionType::CreditCard => write!(f, "Credit Card"),
            RedactionType::Email => write!(f, "Email"),
            RedactionType::Phone => write!(f, "Phone"),
            RedactionType::IpAddress => write!(f, "IP Address"),
            RedactionType::ApiKey => write!(f, "API Key"),
            RedactionType::Password => write!(f, "Password"),
            RedactionType::OtherPii => write!(f, "Other PII"),
        }
    }
}

/// Safety level classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SafetyLevel {
    /// Content is safe
    Safe,
    /// Content is controversial/context-dependent
    Controversial,
    /// Content is unsafe
    Unsafe,
}

/// Request context for guard operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardContext {
    /// Unique request ID
    pub request_id: Uuid,
    /// User identifier (optional)
    pub user_id: Option<String>,
    /// Session identifier (optional)
    pub session_id: Option<String>,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Source IP (for rate limiting)
    pub source_ip: Option<String>,
    /// Additional metadata
    pub metadata: serde_json::Value,
}

impl Default for GuardContext {
    fn default() -> Self {
        Self {
            request_id: Uuid::new_v4(),
            user_id: None,
            session_id: None,
            timestamp: Utc::now(),
            source_ip: None,
            metadata: serde_json::Value::Null,
        }
    }
}

impl GuardContext {
    /// Create a new context with a fresh request ID
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the user ID
    pub fn with_user_id(mut self, user_id: impl Into<String>) -> Self {
        self.user_id = Some(user_id.into());
        self
    }

    /// Set the session ID
    pub fn with_session_id(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }

    /// Set the source IP
    pub fn with_source_ip(mut self, ip: impl Into<String>) -> Self {
        self.source_ip = Some(ip.into());
        self
    }

    /// Set metadata
    pub fn with_metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = metadata;
        self
    }
}

/// Audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Request context
    pub context: GuardContext,
    /// Direction (input/output)
    pub direction: Direction,
    /// Original content hash
    pub content_hash: String,
    /// Result of sanitization
    pub result: AuditResult,
    /// Processing time in milliseconds
    pub processing_time_ms: u64,
}

/// Direction of content flow
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    /// Input to LLM
    Input,
    /// Output from LLM
    Output,
}

/// Result for audit logging (simplified)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditResult {
    /// Content passed
    Passed,
    /// Content was redacted
    Redacted { count: usize },
    /// Content was blocked
    Blocked { category: SafetyCategory },
}

//! Audit logging for Guard

use crate::config::AuditConfig;
use crate::error::SafetyCategory;
use crate::types::{AuditEntry, AuditResult, Direction, GuardContext, SanitizeResult};

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

#[cfg(feature = "audit")]
use tracing::{info, warn};

/// Audit logger
pub struct AuditLogger {
    config: AuditConfig,
}

impl AuditLogger {
    /// Create a new audit logger
    pub fn new(config: AuditConfig) -> Self {
        Self { config }
    }

    /// Log a sanitization event
    pub fn log(
        &self,
        context: &GuardContext,
        direction: Direction,
        content: &str,
        result: &SanitizeResult,
        duration_ms: u64,
    ) {
        if !self.config.enabled {
            return;
        }

        let entry = AuditEntry {
            context: context.clone(),
            direction,
            content_hash: hash_content(content),
            result: match result {
                SanitizeResult::Clean(_) => AuditResult::Passed,
                SanitizeResult::Redacted { redactions, .. } => AuditResult::Redacted {
                    count: redactions.len(),
                },
                SanitizeResult::Blocked { category, .. } => AuditResult::Blocked {
                    category: *category,
                },
            },
            processing_time_ms: duration_ms,
        };

        self.emit(&entry, content);
    }

    /// Log a blocked request
    pub fn log_blocked(
        &self,
        context: &GuardContext,
        direction: Direction,
        content: &str,
        reason: &str,
        category: SafetyCategory,
    ) {
        if !self.config.enabled {
            return;
        }

        let entry = AuditEntry {
            context: context.clone(),
            direction,
            content_hash: hash_content(content),
            result: AuditResult::Blocked { category },
            processing_time_ms: 0,
        };

        #[cfg(feature = "audit")]
        warn!(
            request_id = %context.request_id,
            user_id = ?context.user_id,
            direction = ?direction,
            category = ?category,
            reason = reason,
            "Request blocked"
        );

        self.emit(&entry, content);
    }

    /// Emit an audit entry
    fn emit(&self, entry: &AuditEntry, content: &str) {
        // Log to stdout
        if self.config.log_stdout {
            let content_info = if self.config.log_content {
                format!(", content={}", truncate(content, 100))
            } else {
                String::new()
            };

            println!(
                "[AUDIT] {} | {} | {:?} | result={:?} | {}ms{}",
                entry.context.timestamp.format("%Y-%m-%d %H:%M:%S"),
                entry.context.request_id,
                entry.direction,
                entry.result,
                entry.processing_time_ms,
                content_info
            );
        }

        // Log via tracing
        #[cfg(feature = "audit")]
        {
            let content_field = if self.config.log_content {
                Some(truncate(content, 500))
            } else {
                None
            };

            info!(
                request_id = %entry.context.request_id,
                user_id = ?entry.context.user_id,
                session_id = ?entry.context.session_id,
                direction = ?entry.direction,
                content_hash = %entry.content_hash,
                result = ?entry.result,
                processing_time_ms = entry.processing_time_ms,
                content = ?content_field,
                "Guard audit"
            );
        }

        // Log to file
        if let Some(ref path) = self.config.log_file {
            if let Ok(json) = serde_json::to_string(&entry) {
                // In production, use async file I/O
                let _ = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .and_then(|mut f| {
                        use std::io::Write;
                        writeln!(f, "{json}")
                    });
            }
        }
    }
}

/// Hash content for audit (privacy-preserving)
fn hash_content(content: &str) -> String {
    let mut hasher = DefaultHasher::new();
    content.hash(&mut hasher);
    format!("{:x}", hasher.finish())
}

/// Truncate string for logging
fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_content() {
        let hash1 = hash_content("test");
        let hash2 = hash_content("test");
        let hash3 = hash_content("different");

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_truncate() {
        assert_eq!(truncate("short", 10), "short");
        assert_eq!(truncate("this is a longer string", 10), "this is a ...");
    }

    #[test]
    fn test_audit_disabled() {
        let config = AuditConfig {
            enabled: false,
            ..Default::default()
        };
        let logger = AuditLogger::new(config);

        // Should not panic when disabled
        let ctx = GuardContext::default();
        logger.log(
            &ctx,
            Direction::Input,
            "test content",
            &SanitizeResult::Clean("test content".to_string()),
            10,
        );
    }
}

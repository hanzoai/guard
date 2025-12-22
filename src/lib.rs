//! # Hanzo Guard
//!
//! LLM I/O sanitization and safety layer - the "condom" for AI.
//!
//! Hanzo Guard sits between your application and LLM providers, sanitizing
//! all inputs and outputs to prevent:
//!
//! - **PII Leakage**: Detects and redacts personal identifiable information
//! - **Prompt Injection**: Detects jailbreak and manipulation attempts
//! - **Unsafe Content**: Filters harmful content via Zen Guard models
//! - **Rate Abuse**: Prevents excessive API usage
//! - **Audit Violations**: Logs all requests for compliance
//!
//! ## Quick Start
//!
//! ```rust
//! use hanzo_guard::{Guard, GuardConfig, SanitizeResult};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let guard = Guard::new(GuardConfig::default());
//!
//!     // Sanitize input before sending to LLM
//!     let input = "My SSN is 123-45-6789, can you help me?";
//!     let result = guard.sanitize_input(input).await?;
//!
//!     match result {
//!         SanitizeResult::Clean(text) => {
//!             // Safe to send to LLM
//!             println!("Clean: {}", text);
//!         }
//!         SanitizeResult::Redacted { text, redactions } => {
//!             // PII was redacted
//!             println!("Redacted: {} ({} items)", text, redactions.len());
//!         }
//!         SanitizeResult::Blocked { reason, category } => {
//!             // Content blocked
//!             println!("Blocked: {} ({:?})", reason, category);
//!         }
//!     }
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────┐     ┌──────────────┐     ┌─────────────┐
//! │ Application │ ──► │ Hanzo Guard  │ ──► │ LLM Provider│
//! └─────────────┘     │              │     └─────────────┘
//!                     │ ┌──────────┐ │
//!                     │ │ PII      │ │
//!                     │ │ Detector │ │
//!                     │ └──────────┘ │
//!                     │ ┌──────────┐ │
//!                     │ │ Injection│ │
//!                     │ │ Detector │ │
//!                     │ └──────────┘ │
//!                     │ ┌──────────┐ │
//!                     │ │ Content  │ │
//!                     │ │ Filter   │ │
//!                     │ └──────────┘ │
//!                     │ ┌──────────┐ │
//!                     │ │ Rate     │ │
//!                     │ │ Limiter  │ │
//!                     │ └──────────┘ │
//!                     │ ┌──────────┐ │
//!                     │ │ Audit    │ │
//!                     │ │ Logger   │ │
//!                     │ └──────────┘ │
//!                     └──────────────┘
//! ```

pub mod audit;
pub mod config;
pub mod content;
pub mod error;
pub mod guard;
pub mod injection;
pub mod pii;
pub mod rate_limit;
pub mod types;

pub use config::GuardConfig;
pub use error::{GuardError, Result};
pub use guard::Guard;
pub use types::*;

/// Prelude for convenient imports
pub mod prelude {
    pub use crate::config::GuardConfig;
    pub use crate::error::{GuardError, Result};
    pub use crate::guard::Guard;
    pub use crate::types::*;
}

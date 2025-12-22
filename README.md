# Hanzo Guard

[![Crates.io](https://img.shields.io/crates/v/hanzo-guard.svg)](https://crates.io/crates/hanzo-guard)
[![Documentation](https://docs.rs/hanzo-guard/badge.svg)](https://docs.rs/hanzo-guard)
[![CI](https://github.com/hanzoai/guard/actions/workflows/ci.yml/badge.svg)](https://github.com/hanzoai/guard/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)

Fast, comprehensive LLM I/O sanitization for Rust. Sub-millisecond latency.

## Features

- **PII Detection & Redaction**: SSN, credit cards (Luhn validated), emails, phone numbers, IP addresses, API keys
- **Prompt Injection Detection**: Jailbreak attempts, system prompt leaks, role-play manipulation
- **Rate Limiting**: Per-user request throttling with configurable burst handling
- **Content Filtering**: ML-based safety classification (via external API)
- **Audit Logging**: JSONL audit trails with content hashing

## Installation

```bash
cargo add hanzo-guard
```

Or add to `Cargo.toml`:

```toml
[dependencies]
hanzo-guard = "0.1"
```

## Quick Start

```rust
use hanzo_guard::{Guard, GuardConfig, SanitizeResult};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let guard = Guard::new(GuardConfig::default());

    let result = guard.sanitize_input("My SSN is 123-45-6789").await?;

    match result {
        SanitizeResult::Clean(text) => println!("Clean: {text}"),
        SanitizeResult::Redacted { text, redactions } => {
            println!("Redacted: {text}");
            println!("Found {} PII items", redactions.len());
        }
        SanitizeResult::Blocked { reason, .. } => {
            println!("Blocked: {reason}");
        }
    }

    Ok(())
}
```

## CLI Usage

```bash
# Install
cargo install hanzo-guard --features full

# Pipe text
echo "My email is test@example.com" | hanzo-guard

# From file
hanzo-guard --file input.txt

# JSON output
hanzo-guard --text "SSN: 123-45-6789" --json
```

## Configuration

### Builder Pattern

```rust
let guard = Guard::builder()
    .pii_only()           // Only PII detection
    .with_injection()     // Add injection detection
    .with_rate_limit()    // Add rate limiting
    .build();
```

### Full Configuration

```rust
use hanzo_guard::config::*;

let config = GuardConfig {
    pii: PiiConfig {
        enabled: true,
        detect_ssn: true,
        detect_credit_card: true,
        detect_email: true,
        detect_phone: true,
        detect_ip: true,
        detect_api_keys: true,
        redaction_format: "[REDACTED:{TYPE}]".into(),
    },
    injection: InjectionConfig {
        enabled: true,
        block_on_detection: true,
        sensitivity: 0.7,
        custom_patterns: vec![],
    },
    rate_limit: RateLimitConfig {
        enabled: true,
        requests_per_minute: 60,
        burst_size: 10,
    },
    audit: AuditConfig {
        enabled: true,
        log_path: Some("/var/log/hanzo-guard.jsonl".into()),
        ..Default::default()
    },
    ..Default::default()
};

let guard = Guard::new(config);
```

## Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `pii` | Yes | PII detection and redaction |
| `rate-limit` | Yes | Rate limiting with governor |
| `content-filter` | No | External ML content classification |
| `audit` | Yes | Audit logging |

```toml
# Minimal
hanzo-guard = { version = "0.1", default-features = false }

# PII only
hanzo-guard = { version = "0.1", default-features = false, features = ["pii"] }

# Full
hanzo-guard = { version = "0.1", features = ["full"] }
```

## Performance

| Operation | Latency | Throughput |
|-----------|---------|------------|
| PII Detection | ~50μs | 20K+ ops/sec |
| Injection Check | ~20μs | 50K+ ops/sec |
| Full Sanitize | ~100μs | 10K+ ops/sec |
| Rate Limit Check | ~1μs | 1M+ ops/sec |

*Benchmarked on Apple M1 Max, single-threaded*

## Safety Categories

Content is classified into:

- **Violent**: Violence instructions or depictions
- **Illegal**: Hacking, unauthorized activities
- **Sexual**: Adult content
- **PII**: Personal information disclosure
- **SelfHarm**: Self-harm encouragement
- **Unethical**: Bias, discrimination, hate
- **Jailbreak**: System prompt override attempts

## License

Dual licensed under MIT OR Apache-2.0.

## Related

- [hanzo-extract](https://github.com/hanzoai/extract) - Content extraction with guard integration
- [Hanzo AI](https://hanzo.ai) - AI infrastructure platform

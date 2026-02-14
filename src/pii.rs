//! PII (Personally Identifiable Information) detection and redaction

use crate::config::PiiConfig;
use crate::types::{Redaction, RedactionType};

#[cfg(feature = "pii")]
use regex::Regex;

/// PII detector for identifying and redacting sensitive information
pub struct PiiDetector {
    config: PiiConfig,
    #[cfg(feature = "pii")]
    patterns: PiiPatterns,
}

#[cfg(feature = "pii")]
struct PiiPatterns {
    ssn: Regex,
    credit_card: Regex,
    email: Regex,
    phone: Regex,
    ip_v4: Regex,
    ip_v6: Regex,
    api_key: Regex,
}

#[cfg(feature = "pii")]
impl PiiPatterns {
    fn new() -> Self {
        Self {
            // SSN: 123-45-6789 or 123456789
            ssn: Regex::new(r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b").unwrap(),
            // Credit cards: 16 digits with optional separators
            credit_card: Regex::new(
                r"\b(?:\d{4}[-\s]?){3}\d{4}\b|\b\d{15,16}\b"
            ).unwrap(),
            // Email addresses
            email: Regex::new(
                r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
            ).unwrap(),
            // Phone numbers (various formats)
            phone: Regex::new(
                r"\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b"
            ).unwrap(),
            // IPv4 addresses
            ip_v4: Regex::new(
                r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
            ).unwrap(),
            // IPv6 addresses (simplified)
            ip_v6: Regex::new(
                r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"
            ).unwrap(),
            // API keys (common patterns)
            api_key: Regex::new(
                r#"\b(?:sk-[a-zA-Z0-9]{20,}|api[_-]?key[=:\s]+['"]?[a-zA-Z0-9_-]{20,}['"]?)\b"#
            ).unwrap(),
        }
    }
}

impl PiiDetector {
    /// Create a new PII detector with the given configuration
    pub fn new(config: PiiConfig) -> Self {
        Self {
            config,
            #[cfg(feature = "pii")]
            patterns: PiiPatterns::new(),
        }
    }

    /// Detect all PII in the given text
    #[cfg(feature = "pii")]
    pub fn detect(&self, text: &str) -> Vec<Redaction> {
        if !self.config.enabled {
            return vec![];
        }

        let mut redactions = vec![];

        // Detect SSNs
        if self.config.detect_ssn {
            for m in self.patterns.ssn.find_iter(text) {
                redactions.push(Redaction {
                    redaction_type: RedactionType::Ssn,
                    original_hash: hash_value(m.as_str()),
                    replacement: self.format_redaction(RedactionType::Ssn),
                    start: m.start(),
                    end: m.end(),
                });
            }
        }

        // Detect credit cards
        if self.config.detect_credit_card {
            for m in self.patterns.credit_card.find_iter(text) {
                // Validate Luhn algorithm for credit cards
                let digits: String = m.as_str().chars().filter(|c| c.is_ascii_digit()).collect();
                if luhn_check(&digits) {
                    redactions.push(Redaction {
                        redaction_type: RedactionType::CreditCard,
                        original_hash: hash_value(m.as_str()),
                        replacement: self.format_redaction(RedactionType::CreditCard),
                        start: m.start(),
                        end: m.end(),
                    });
                }
            }
        }

        // Detect emails
        if self.config.detect_email {
            for m in self.patterns.email.find_iter(text) {
                redactions.push(Redaction {
                    redaction_type: RedactionType::Email,
                    original_hash: hash_value(m.as_str()),
                    replacement: self.format_redaction(RedactionType::Email),
                    start: m.start(),
                    end: m.end(),
                });
            }
        }

        // Detect phone numbers
        if self.config.detect_phone {
            for m in self.patterns.phone.find_iter(text) {
                redactions.push(Redaction {
                    redaction_type: RedactionType::Phone,
                    original_hash: hash_value(m.as_str()),
                    replacement: self.format_redaction(RedactionType::Phone),
                    start: m.start(),
                    end: m.end(),
                });
            }
        }

        // Detect IP addresses
        if self.config.detect_ip {
            for m in self.patterns.ip_v4.find_iter(text) {
                redactions.push(Redaction {
                    redaction_type: RedactionType::IpAddress,
                    original_hash: hash_value(m.as_str()),
                    replacement: self.format_redaction(RedactionType::IpAddress),
                    start: m.start(),
                    end: m.end(),
                });
            }
            for m in self.patterns.ip_v6.find_iter(text) {
                redactions.push(Redaction {
                    redaction_type: RedactionType::IpAddress,
                    original_hash: hash_value(m.as_str()),
                    replacement: self.format_redaction(RedactionType::IpAddress),
                    start: m.start(),
                    end: m.end(),
                });
            }
        }

        // Detect API keys
        if self.config.detect_api_keys {
            for m in self.patterns.api_key.find_iter(text) {
                redactions.push(Redaction {
                    redaction_type: RedactionType::ApiKey,
                    original_hash: hash_value(m.as_str()),
                    replacement: self.format_redaction(RedactionType::ApiKey),
                    start: m.start(),
                    end: m.end(),
                });
            }
        }

        // Sort by position and remove overlaps
        redactions.sort_by_key(|r| r.start);
        remove_overlaps(&mut redactions);

        redactions
    }

    /// Detect PII (stub when feature disabled)
    #[cfg(not(feature = "pii"))]
    pub fn detect(&self, _text: &str) -> Vec<Redaction> {
        vec![]
    }

    /// Redact PII from text
    pub fn redact(&self, text: &str, redactions: &[Redaction]) -> String {
        if redactions.is_empty() {
            return text.to_string();
        }

        let mut result = String::with_capacity(text.len());
        let mut last_end = 0;

        for redaction in redactions {
            // Add text before the redaction
            if redaction.start > last_end {
                result.push_str(&text[last_end..redaction.start]);
            }
            // Add the replacement
            result.push_str(&redaction.replacement);
            last_end = redaction.end;
        }

        // Add remaining text
        if last_end < text.len() {
            result.push_str(&text[last_end..]);
        }

        result
    }

    /// Format redaction placeholder
    fn format_redaction(&self, redaction_type: RedactionType) -> String {
        self.config
            .redaction_format
            .replace("{TYPE}", &redaction_type.to_string())
    }
}

/// Hash a value for audit logging (without storing the original)
fn hash_value(value: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    format!("{:x}", hasher.finish())
}

/// Luhn algorithm for credit card validation
#[cfg(feature = "pii")]
fn luhn_check(number: &str) -> bool {
    let digits: Vec<u32> = number.chars().filter_map(|c| c.to_digit(10)).collect();

    if digits.len() < 13 {
        return false;
    }

    let mut sum = 0;
    let mut double = false;

    for &digit in digits.iter().rev() {
        let mut d = digit;
        if double {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
        double = !double;
    }

    sum % 10 == 0
}

/// Remove overlapping redactions (keep the first one)
fn remove_overlaps(redactions: &mut Vec<Redaction>) {
    if redactions.len() < 2 {
        return;
    }

    let mut i = 0;
    while i < redactions.len() - 1 {
        if redactions[i].end > redactions[i + 1].start {
            redactions.remove(i + 1);
        } else {
            i += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssn_detection() {
        let config = PiiConfig::default();
        let detector = PiiDetector::new(config);

        let text = "My SSN is 123-45-6789 and yours is 987654321";
        let redactions = detector.detect(text);

        assert_eq!(redactions.len(), 2);
        assert_eq!(redactions[0].redaction_type, RedactionType::Ssn);
    }

    #[test]
    fn test_email_detection() {
        let config = PiiConfig::default();
        let detector = PiiDetector::new(config);

        let text = "Contact me at john.doe@example.com for more info";
        let redactions = detector.detect(text);

        assert!(redactions
            .iter()
            .any(|r| r.redaction_type == RedactionType::Email));
    }

    #[test]
    fn test_redaction() {
        let config = PiiConfig::default();
        let detector = PiiDetector::new(config);

        let text = "My email is test@test.com";
        let redactions = detector.detect(text);
        let redacted = detector.redact(text, &redactions);

        assert!(!redacted.contains("test@test.com"));
        assert!(redacted.contains("[REDACTED:Email]"));
    }

    #[test]
    fn test_credit_card_luhn() {
        // Valid test card number
        assert!(luhn_check("4532015112830366"));
        // Invalid number
        assert!(!luhn_check("1234567890123456"));
    }
}

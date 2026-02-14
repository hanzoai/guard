//! Content filtering via Zen Guard API

use crate::config::ContentFilterConfig;
#[cfg(feature = "content-filter")]
use crate::error::GuardError;
use crate::error::{Result, SafetyCategory};
use crate::types::SafetyLevel;
#[cfg(feature = "content-filter")]
use serde::{Deserialize, Serialize};

/// Content filter using Zen Guard models
pub struct ContentFilter {
    config: ContentFilterConfig,
    #[cfg(feature = "content-filter")]
    client: reqwest::Client,
}

/// Request to Zen Guard API
#[cfg(feature = "content-filter")]
#[derive(Debug, Serialize)]
struct GuardRequest {
    messages: Vec<GuardMessage>,
}

#[cfg(feature = "content-filter")]
#[derive(Debug, Serialize)]
struct GuardMessage {
    role: String,
    content: String,
}

/// Response from Zen Guard API
#[cfg(feature = "content-filter")]
#[derive(Debug, Deserialize)]
struct GuardResponse {
    safety: String,
    categories: Vec<String>,
    refusal: Option<String>,
}

/// Content filter result
#[derive(Debug, Clone)]
pub struct ContentFilterResult {
    /// Safety level
    pub safety_level: SafetyLevel,
    /// Categories detected
    pub categories: Vec<SafetyCategory>,
    /// Whether content was refused
    pub refused: bool,
}

impl ContentFilter {
    /// Create a new content filter
    pub fn new(config: ContentFilterConfig) -> Self {
        Self {
            config,
            #[cfg(feature = "content-filter")]
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_millis(5000))
                .build()
                .unwrap_or_default(),
        }
    }

    /// Check content safety
    #[cfg(feature = "content-filter")]
    pub async fn check(&self, content: &str, is_response: bool) -> Result<ContentFilterResult> {
        if !self.config.enabled {
            return Ok(ContentFilterResult {
                safety_level: SafetyLevel::Safe,
                categories: vec![],
                refused: false,
            });
        }

        let messages = if is_response {
            vec![
                GuardMessage {
                    role: "user".to_string(),
                    content: "[Checking response]".to_string(),
                },
                GuardMessage {
                    role: "assistant".to_string(),
                    content: content.to_string(),
                },
            ]
        } else {
            vec![GuardMessage {
                role: "user".to_string(),
                content: content.to_string(),
            }]
        };

        let request = GuardRequest { messages };

        let mut req = self
            .client
            .post(&self.config.api_endpoint)
            .json(&request)
            .timeout(std::time::Duration::from_millis(self.config.timeout_ms));

        if let Some(ref api_key) = self.config.api_key {
            req = req.header("Authorization", format!("Bearer {}", api_key));
        }

        let response = req
            .send()
            .await
            .map_err(|e| GuardError::ContentFilterError(format!("API request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(GuardError::ContentFilterError(format!(
                "API returned status: {}",
                response.status()
            )));
        }

        let guard_response: GuardResponse = response.json().await.map_err(|e| {
            GuardError::ContentFilterError(format!("Failed to parse response: {}", e))
        })?;

        let safety_level = match guard_response.safety.to_lowercase().as_str() {
            "safe" => SafetyLevel::Safe,
            "controversial" => SafetyLevel::Controversial,
            "unsafe" => SafetyLevel::Unsafe,
            _ => SafetyLevel::Safe,
        };

        let categories = guard_response
            .categories
            .iter()
            .filter_map(|c| parse_category(c))
            .collect();

        let refused = guard_response.refusal.as_deref() == Some("Yes");

        Ok(ContentFilterResult {
            safety_level,
            categories,
            refused,
        })
    }

    /// Check content safety (stub when feature disabled)
    #[cfg(not(feature = "content-filter"))]
    pub async fn check(&self, _content: &str, _is_response: bool) -> Result<ContentFilterResult> {
        Ok(ContentFilterResult {
            safety_level: SafetyLevel::Safe,
            categories: vec![],
            refused: false,
        })
    }

    /// Check if content should be blocked based on result
    pub fn should_block(&self, result: &ContentFilterResult) -> Option<(String, SafetyCategory)> {
        match result.safety_level {
            SafetyLevel::Unsafe => {
                let category = result
                    .categories
                    .first()
                    .copied()
                    .unwrap_or(SafetyCategory::None);
                Some((
                    format!("Content classified as unsafe: {:?}", result.categories),
                    category,
                ))
            }
            SafetyLevel::Controversial if self.config.block_controversial => {
                let category = result
                    .categories
                    .first()
                    .copied()
                    .unwrap_or(SafetyCategory::None);
                Some((
                    format!(
                        "Content classified as controversial: {:?}",
                        result.categories
                    ),
                    category,
                ))
            }
            _ => None,
        }
    }
}

/// Parse category string to enum
#[cfg(any(feature = "content-filter", test))]
fn parse_category(category: &str) -> Option<SafetyCategory> {
    match category.to_lowercase().as_str() {
        "violent" => Some(SafetyCategory::Violent),
        "non-violent illegal acts" | "illegalacts" => Some(SafetyCategory::IllegalActs),
        "sexual content or sexual acts" | "sexualcontent" => Some(SafetyCategory::SexualContent),
        "pii" | "personally identifiable information" => Some(SafetyCategory::Pii),
        "suicide & self-harm" | "selfharm" => Some(SafetyCategory::SelfHarm),
        "unethical acts" | "unethicalacts" => Some(SafetyCategory::UnethicalActs),
        "politically sensitive topics" | "politicallysensitive" => {
            Some(SafetyCategory::PoliticallySensitive)
        }
        "copyright violation" | "copyrightviolation" => Some(SafetyCategory::CopyrightViolation),
        "jailbreak" => Some(SafetyCategory::Jailbreak),
        "none" => Some(SafetyCategory::None),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_category() {
        assert_eq!(parse_category("Violent"), Some(SafetyCategory::Violent));
        assert_eq!(parse_category("jailbreak"), Some(SafetyCategory::Jailbreak));
        assert_eq!(parse_category("PII"), Some(SafetyCategory::Pii));
    }

    #[test]
    fn test_should_block_unsafe() {
        let config = ContentFilterConfig::default();
        let filter = ContentFilter::new(config);

        let result = ContentFilterResult {
            safety_level: SafetyLevel::Unsafe,
            categories: vec![SafetyCategory::Violent],
            refused: false,
        };

        assert!(filter.should_block(&result).is_some());
    }

    #[test]
    fn test_should_not_block_safe() {
        let config = ContentFilterConfig::default();
        let filter = ContentFilter::new(config);

        let result = ContentFilterResult {
            safety_level: SafetyLevel::Safe,
            categories: vec![],
            refused: false,
        };

        assert!(filter.should_block(&result).is_none());
    }
}

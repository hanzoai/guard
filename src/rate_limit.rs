//! Rate limiting for Guard

use crate::config::RateLimitConfig;
use crate::error::{GuardError, Result};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[cfg(feature = "rate-limit")]
use governor::{Quota, RateLimiter as GovernorLimiter};
#[cfg(feature = "rate-limit")]
use std::num::NonZeroU32;

/// Rate limiter for API requests
pub struct RateLimiter {
    config: RateLimitConfig,
    #[cfg(feature = "rate-limit")]
    limiters: Arc<
        RwLock<
            HashMap<
                String,
                Arc<
                    GovernorLimiter<
                        governor::state::NotKeyed,
                        governor::state::InMemoryState,
                        governor::clock::DefaultClock,
                    >,
                >,
            >,
        >,
    >,
}

impl RateLimiter {
    /// Create a new rate limiter
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            #[cfg(feature = "rate-limit")]
            limiters: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Check if a request is allowed
    #[cfg(feature = "rate-limit")]
    pub async fn check(&self, user_id: &str) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        let limiter = self.get_or_create_limiter(user_id).await;

        match limiter.check() {
            Ok(_) => Ok(()),
            Err(_) => Err(GuardError::RateLimitExceeded(format!(
                "Rate limit exceeded for user: {}. Limit: {} requests/minute",
                user_id, self.config.requests_per_minute
            ))),
        }
    }

    /// Check if a request is allowed (stub when feature disabled)
    #[cfg(not(feature = "rate-limit"))]
    pub async fn check(&self, _user_id: &str) -> Result<()> {
        Ok(())
    }

    /// Get or create a limiter for a user
    #[cfg(feature = "rate-limit")]
    async fn get_or_create_limiter(
        &self,
        user_id: &str,
    ) -> Arc<
        GovernorLimiter<
            governor::state::NotKeyed,
            governor::state::InMemoryState,
            governor::clock::DefaultClock,
        >,
    > {
        // Try to get existing limiter
        {
            let limiters = self.limiters.read().await;
            if let Some(limiter) = limiters.get(user_id) {
                return limiter.clone();
            }
        }

        // Create new limiter
        let mut limiters = self.limiters.write().await;

        // Double-check after acquiring write lock
        if let Some(limiter) = limiters.get(user_id) {
            return limiter.clone();
        }

        let quota = Quota::per_minute(
            NonZeroU32::new(self.config.requests_per_minute)
                .unwrap_or(NonZeroU32::new(60).unwrap()),
        )
        .allow_burst(
            NonZeroU32::new(self.config.burst_size).unwrap_or(NonZeroU32::new(10).unwrap()),
        );

        let limiter = Arc::new(GovernorLimiter::direct(quota));
        limiters.insert(user_id.to_string(), limiter.clone());

        limiter
    }

    /// Clean up old limiters (call periodically)
    #[cfg(feature = "rate-limit")]
    pub async fn cleanup(&self) {
        let mut limiters = self.limiters.write().await;
        // In a production system, you'd track last access time
        // and remove limiters that haven't been used recently
        if limiters.len() > 10000 {
            limiters.clear();
        }
    }

    /// Get current limit status for a user
    #[cfg(feature = "rate-limit")]
    pub async fn status(&self, user_id: &str) -> RateLimitStatus {
        if !self.config.enabled {
            return RateLimitStatus {
                allowed: true,
                remaining: self.config.requests_per_minute,
                reset_at: None,
            };
        }

        let limiter = self.get_or_create_limiter(user_id).await;

        match limiter.check() {
            Ok(_) => RateLimitStatus {
                allowed: true,
                remaining: self.config.requests_per_minute, // Approximation
                reset_at: None,
            },
            Err(_) => RateLimitStatus {
                allowed: false,
                remaining: 0,
                reset_at: Some(std::time::Duration::from_secs(60)),
            },
        }
    }

    /// Get current limit status (stub when feature disabled)
    #[cfg(not(feature = "rate-limit"))]
    pub async fn status(&self, _user_id: &str) -> RateLimitStatus {
        RateLimitStatus {
            allowed: true,
            remaining: u32::MAX,
            reset_at: None,
        }
    }
}

/// Rate limit status
#[derive(Debug, Clone)]
pub struct RateLimitStatus {
    /// Whether the request is allowed
    pub allowed: bool,
    /// Remaining requests in the current window
    pub remaining: u32,
    /// Time until reset
    pub reset_at: Option<std::time::Duration>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rate_limit_disabled() {
        let config = RateLimitConfig {
            enabled: false,
            ..Default::default()
        };
        let limiter = RateLimiter::new(config);

        // Should always allow when disabled
        assert!(limiter.check("user1").await.is_ok());
        assert!(limiter.check("user1").await.is_ok());
    }

    #[tokio::test]
    #[cfg(feature = "rate-limit")]
    async fn test_rate_limit_basic() {
        let config = RateLimitConfig {
            enabled: true,
            requests_per_minute: 2,
            burst_size: 2,
            ..Default::default()
        };
        let limiter = RateLimiter::new(config);

        // First two should pass (burst)
        assert!(limiter.check("user1").await.is_ok());
        assert!(limiter.check("user1").await.is_ok());

        // Third should fail
        assert!(limiter.check("user1").await.is_err());
    }
}

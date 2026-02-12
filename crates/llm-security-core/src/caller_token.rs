//! CallerToken creation and validation using HMAC-SHA256.

use crate::error::GatewayError;
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

const DEFAULT_TTL_SECONDS: i64 = 300; // 5 minutes
const MAX_CLOCK_SKEW_SECONDS: i64 = 30;

/// HMAC-signed caller identity token.
/// Required for all scanning operations through the gateway.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CallerToken {
    /// Unique caller identifier (e.g., "agentics-core", "my-service").
    pub caller_id: String,
    /// HMAC-SHA256 signature of `caller_id|issued_at` using the shared secret (hex-encoded).
    pub signature: String,
    /// Token creation timestamp (ISO 8601).
    pub issued_at: String,
}

impl CallerToken {
    /// Create a new signed CallerToken.
    ///
    /// # Arguments
    ///
    /// * `caller_id` - Unique identifier for the caller
    /// * `shared_secret` - Shared secret for HMAC signing
    pub fn create(caller_id: &str, shared_secret: &str) -> Result<Self, GatewayError> {
        if caller_id.is_empty() {
            return Err(GatewayError::InvalidCallerToken(
                "caller_id must not be empty".to_string(),
            ));
        }
        if shared_secret.is_empty() {
            return Err(GatewayError::InvalidCallerToken(
                "shared_secret must not be empty".to_string(),
            ));
        }

        let issued_at = Utc::now().to_rfc3339();
        let signature = compute_signature(caller_id, &issued_at, shared_secret)?;

        Ok(Self {
            caller_id: caller_id.to_string(),
            signature,
            issued_at,
        })
    }

    /// Validate this token's signature and expiry.
    ///
    /// # Arguments
    ///
    /// * `shared_secret` - Shared secret for HMAC verification
    /// * `ttl_seconds` - Maximum token age in seconds (None = use default 300s)
    pub fn validate(
        &self,
        shared_secret: &str,
        ttl_seconds: Option<i64>,
    ) -> Result<(), GatewayError> {
        let ttl = ttl_seconds.unwrap_or(DEFAULT_TTL_SECONDS);

        // Check required fields
        if self.caller_id.is_empty() {
            return Err(GatewayError::InvalidCallerToken(
                "caller_id is empty".to_string(),
            ));
        }
        if self.signature.is_empty() {
            return Err(GatewayError::InvalidCallerToken(
                "signature is empty".to_string(),
            ));
        }
        if self.issued_at.is_empty() {
            return Err(GatewayError::InvalidCallerToken(
                "issued_at is empty".to_string(),
            ));
        }

        // Verify HMAC signature
        let expected_signature =
            compute_signature(&self.caller_id, &self.issued_at, shared_secret)?;

        // Constant-time comparison via HMAC verify
        let payload = format!("{}|{}", self.caller_id, self.issued_at);
        let mut mac = HmacSha256::new_from_slice(shared_secret.as_bytes())
            .map_err(|e| GatewayError::InvalidCallerToken(format!("HMAC error: {}", e)))?;
        mac.update(payload.as_bytes());

        let sig_bytes = hex::decode(&self.signature).map_err(|_| {
            GatewayError::InvalidCallerToken("signature is not valid hex".to_string())
        })?;

        mac.verify_slice(&sig_bytes)
            .map_err(|_| GatewayError::InvalidCallerToken("signature mismatch".to_string()))?;

        // Check expiry
        let issued_at: DateTime<Utc> = self
            .issued_at
            .parse()
            .map_err(|_| GatewayError::InvalidCallerToken("invalid issued_at timestamp".to_string()))?;

        let now = Utc::now();
        let age = now.signed_duration_since(issued_at);

        if age.num_seconds() > ttl {
            return Err(GatewayError::ExpiredCallerToken(format!(
                "age: {}s, TTL: {}s",
                age.num_seconds(),
                ttl
            )));
        }

        if age.num_seconds() < -MAX_CLOCK_SKEW_SECONDS {
            return Err(GatewayError::InvalidCallerToken(
                "issued_at is in the future".to_string(),
            ));
        }

        let _ = expected_signature; // Silence unused warning (we used mac.verify above)
        Ok(())
    }
}

/// Compute HMAC-SHA256 signature, returning hex-encoded string.
fn compute_signature(
    caller_id: &str,
    issued_at: &str,
    secret: &str,
) -> Result<String, GatewayError> {
    let payload = format!("{}|{}", caller_id, issued_at);
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|e| GatewayError::InvalidCallerToken(format!("HMAC error: {}", e)))?;
    mac.update(payload.as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_validate() {
        let token = CallerToken::create("test-service", "my-secret-key").unwrap();
        assert_eq!(token.caller_id, "test-service");
        assert!(!token.signature.is_empty());
        assert!(!token.issued_at.is_empty());

        // Should validate successfully
        token.validate("my-secret-key", None).unwrap();
    }

    #[test]
    fn test_invalid_signature() {
        let mut token = CallerToken::create("test-service", "my-secret-key").unwrap();
        token.signature = "deadbeef".repeat(8); // Wrong signature

        let result = token.validate("my-secret-key", None);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), GatewayError::InvalidCallerToken(_)));
    }

    #[test]
    fn test_wrong_secret() {
        let token = CallerToken::create("test-service", "my-secret-key").unwrap();

        let result = token.validate("wrong-secret", None);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_caller_id() {
        let result = CallerToken::create("", "my-secret-key");
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_secret() {
        let result = CallerToken::create("test-service", "");
        assert!(result.is_err());
    }

    #[test]
    fn test_expired_token() {
        let mut token = CallerToken::create("test-service", "my-secret-key").unwrap();
        // Set issued_at to 10 minutes ago
        let old_time = Utc::now() - chrono::Duration::seconds(600);
        token.issued_at = old_time.to_rfc3339();
        // Re-sign with the old timestamp
        token.signature = compute_signature("test-service", &token.issued_at, "my-secret-key").unwrap();

        let result = token.validate("my-secret-key", Some(300));
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), GatewayError::ExpiredCallerToken(_)));
    }
}

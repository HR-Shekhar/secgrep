//! Finding model. Full secrets are never stored on this type.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    ApiKey,
    AccessToken,
    Password,
    Jwt,
    PrivateKey,
    ConnectionString,
    AuthorizationHeader,
    GenericSecret,
}

impl Category {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ApiKey => "api_key",
            Self::AccessToken => "access_token",
            Self::Password => "password",
            Self::Jwt => "jwt",
            Self::PrivateKey => "private_key",
            Self::ConnectionString => "connection_string",
            Self::AuthorizationHeader => "authorization_header",
            Self::GenericSecret => "generic_secret",
        }
    }

    pub fn parse_config(s: &str) -> Option<Self> {
        match s {
            "api_key" => Some(Self::ApiKey),
            "access_token" => Some(Self::AccessToken),
            "password" => Some(Self::Password),
            "jwt" => Some(Self::Jwt),
            "private_key" => Some(Self::PrivateKey),
            "connection_string" => Some(Self::ConnectionString),
            "authorization_header" => Some(Self::AuthorizationHeader),
            "generic_secret" => Some(Self::GenericSecret),
            _ => None,
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Self::ApiKey => "API key",
            Self::AccessToken => "Access token",
            Self::Password => "Password",
            Self::Jwt => "JWT-like token",
            Self::PrivateKey => "Private key",
            Self::ConnectionString => "Database connection string",
            Self::AuthorizationHeader => "Authorization header",
            Self::GenericSecret => "Generic secret",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    pub fn parse_config(s: &str) -> Option<Self> {
        match s {
            "low" => Some(Self::Low),
            "medium" => Some(Self::Medium),
            "high" => Some(Self::High),
            "critical" => Some(Self::Critical),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidityStatus {
    Verified,
    Likely,
    Suspicious,
    FalsePositive,
    Unknown,
}

impl ValidityStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Likely => "likely",
            Self::Suspicious => "suspicious",
            Self::FalsePositive => "false_positive",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Signals {
    pub pattern: f64,
    pub context: f64,
    pub entropy: f64,
    pub entropy_bits: f64,
    pub file: f64,
    pub validity: f64,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub rule_id: String,
    pub file: String,
    pub line: usize,
    pub column: usize,
    pub category: Category,
    pub redacted_preview: String,
    pub confidence: f64,
    pub severity: Severity,
    pub detector: String,
    pub status: ValidityStatus,
    pub why: Vec<String>,
    pub remediation: Vec<String>,
    pub signals: Signals,
    /// SHA-256 of the secret. Not reversible. Used to join history events.
    pub fingerprint: String,
}

impl Finding {
    pub fn should_block(&self, min_confidence: f64) -> bool {
        self.status != ValidityStatus::FalsePositive && self.confidence >= min_confidence
    }
}

#[derive(Debug, Clone)]
pub struct Candidate {
    pub rule_id: String,
    pub file: String,
    pub line: usize,
    pub column: usize,
    pub category: Category,
    pub severity: Severity,
    pub pattern_strength: f64,
    pub description: String,
    pub raw: String,
    pub line_text: String,
}

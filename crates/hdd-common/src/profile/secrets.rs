//! Types that make it impossible to parse or print a secret through the profile (T-0006 steps 2 and 8, A4).
//!
//! * [`EnvVarName`] holds the NAME of an environment variable. Anything that does not look like such a name (a token,
//!   a key, a URL with credentials) is rejected when the file is parsed.
//! * [`SecretPath`] holds the path of a secret file. Its `Debug`, `Display` and `Serialize` forms show the file name
//!   only, so printing or logging a profile never reveals where the secret lives beyond its name.

use std::borrow::Cow;
use std::fmt;
use std::path::Path;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize, Serializer};

/// Longest accepted environment variable name.
pub const ENV_NAME_MAX: usize = 64;
/// A name without an underscore must not be longer than this (long single-word uppercase strings look like keys).
pub const ENV_NAME_MAX_WITHOUT_UNDERSCORE: usize = 12;
/// Prefixes of well-known credential formats that are never valid names.
const CREDENTIAL_PREFIXES: &[&str] = &["AKIA", "ASIA", "AGPA", "AIDA", "AROA", "ANPA", "AIZA"];

/// Why a string is not an acceptable environment variable name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvNameError {
    /// Not made of uppercase letters, digits and single underscores, or starts with a digit.
    Shape,
    /// Longer than [`ENV_NAME_MAX`].
    TooLong,
    /// Looks like a credential rather than a name.
    LooksLikeCredential,
}

impl fmt::Display for EnvNameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EnvNameError::Shape => f.write_str("must be the NAME of an environment variable (UPPER_CASE letters, digits and underscores, not starting with a digit); never put the secret value in the profile"),
            EnvNameError::TooLong => write!(f, "environment variable names are limited to {ENV_NAME_MAX} characters; this looks like a value, not a name"),
            EnvNameError::LooksLikeCredential => f.write_str("looks like a credential value, not an environment variable name; put the value in the environment and the NAME here"),
        }
    }
}

/// Longest single word accepted inside a name (longer runs of letters look like random keys).
pub const ENV_SEGMENT_MAX: usize = 14;

/// A name segment that looks like random key material rather than a word: a very long run, or a digit followed by a letter
/// inside a segment of five or more characters (`JBSWY3DP`, `PL82MNB4R7`). Words with a trailing number (`OAUTH2`, `NS1`,
/// `SHA256`) are fine. This is a heuristic: it catches pasted base32/base62 secrets, not every possible secret.
fn segment_looks_random(seg: &str) -> bool {
    if seg.len() > ENV_SEGMENT_MAX {
        return true;
    }
    if seg.len() < 5 {
        return false;
    }
    let b = seg.as_bytes();
    b.windows(2)
        .any(|w| matches!(w, [d, l] if d.is_ascii_digit() && l.is_ascii_uppercase()))
}

/// Like [`segment_looks_random`] for mixed-case file name parts: a long run with digits and both letter cases.
fn segment_looks_random_mixed(seg: &str) -> bool {
    seg.len() >= 24
        && seg.chars().any(|c| c.is_ascii_digit())
        && seg.chars().any(|c| c.is_ascii_lowercase())
        && seg.chars().any(|c| c.is_ascii_uppercase())
}

/// Name of an environment variable (empty means "not configured").
#[derive(Clone, PartialEq, Eq, Default)]
pub struct EnvVarName(String);

impl EnvVarName {
    /// The unset value.
    pub fn empty() -> Self {
        EnvVarName(String::new())
    }

    /// Validate and wrap a name. The empty string is allowed and means unset.
    pub fn parse(s: &str) -> Result<Self, EnvNameError> {
        if s.is_empty() {
            return Ok(Self::empty());
        }
        if s.len() > ENV_NAME_MAX {
            return Err(EnvNameError::TooLong);
        }
        let mut chars = s.chars();
        let first_ok = chars.next().is_some_and(|c| c.is_ascii_uppercase());
        let body_ok = s
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
        let no_double_or_trailing_underscore = !s.contains("__") && !s.ends_with('_');
        if !(first_ok && body_ok && no_double_or_trailing_underscore) {
            return Err(EnvNameError::Shape);
        }
        if CREDENTIAL_PREFIXES.iter().any(|p| s.starts_with(p)) && !s.contains('_') {
            return Err(EnvNameError::LooksLikeCredential);
        }
        if !s.contains('_') && s.len() > ENV_NAME_MAX_WITHOUT_UNDERSCORE {
            return Err(EnvNameError::LooksLikeCredential);
        }
        if s.split('_').any(segment_looks_random) {
            return Err(EnvNameError::LooksLikeCredential);
        }
        Ok(EnvVarName(s.to_owned()))
    }

    /// The name (empty when unset).
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// True when no name is configured.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for EnvVarName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EnvVarName({:?})", self.0)
    }
}

impl Serialize for EnvVarName {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for EnvVarName {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        EnvVarName::parse(&raw).map_err(|e| de::Error::custom(e.to_string()))
    }
}

impl JsonSchema for EnvVarName {
    fn schema_name() -> Cow<'static, str> {
        Cow::Borrowed("EnvVarName")
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "maxLength": ENV_NAME_MAX,
            "pattern": "^([A-Z][A-Z0-9]*(_[A-Z0-9]+)*)?$",
            "description": "The NAME of an environment variable (never its value). Empty means not configured."
        })
    }
}

/// Path of a secret file; every printed or serialized form shows the file name only.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct SecretPath(String);

impl SecretPath {
    /// Wrap a path.
    pub fn new(p: impl Into<String>) -> Self {
        SecretPath(p.into())
    }

    /// The real path, for code that must open the file. Never print this.
    pub fn expose_path(&self) -> &str {
        &self.0
    }

    /// True when not configured.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The file name only (the redacted form).
    pub fn file_name(&self) -> String {
        if self.0.is_empty() {
            return String::new();
        }
        let normalized = self.0.replace('\\', "/");
        let name = Path::new(&normalized)
            .file_name()
            .map_or_else(|| "<path>".to_owned(), |n| n.to_string_lossy().into_owned());
        // a value pasted into a path field (a token has no directory part) must not be echoed as if it were a file name
        let has_directory = self.0.contains('/') || self.0.contains('\\');
        let plausible = (has_directory || name.contains('.') || name.len() <= 16)
            && name.len() <= 64
            && name.chars().all(|c| {
                c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ' ' | '(' | ')')
            })
            && !name
                .split(['.', '_', '-'])
                .any(|seg| segment_looks_random_mixed(seg) || segment_looks_random(seg));
        if plausible {
            name
        } else {
            "<redacted>".to_owned()
        }
    }
}

impl fmt::Debug for SecretPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretPath(…/{})", self.file_name())
    }
}

impl fmt::Display for SecretPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            Ok(())
        } else {
            write!(f, "…/{}", self.file_name())
        }
    }
}

impl Serialize for SecretPath {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for SecretPath {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(SecretPath(String::deserialize(d)?))
    }
}

impl JsonSchema for SecretPath {
    fn schema_name() -> Cow<'static, str> {
        Cow::Borrowed("SecretPath")
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "description": "Path of a secret file. Printed and logged as its file name only."
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plausible_names_are_accepted() {
        for ok in [
            "",
            "HDD_SMTP_PASSWORD",
            "SMTP_USER",
            "TOKEN",
            "A1_B2",
            "REGISTRAR_API_TOKEN",
        ] {
            assert!(EnvVarName::parse(ok).is_ok(), "{ok}");
        }
    }

    #[test]
    fn token_looking_values_are_rejected() {
        let github = format!("{}_{}", "ghp", "abcdefghijklmnopqrstuvwxyz0123456789"); // hdd-secret-scan:allow (test vector)
        let aws = format!("{}{}", "AKIA", "IOSFODNN7EXAMPLE");
        let jwt_like = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc";
        let url = "https://user:pw@host";
        let long_upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"; // hdd-secret-scan:allow (test vector)
        for bad in [
            github.as_str(),
            aws.as_str(),
            jwt_like,
            url,
            long_upper,
            "lower_case",
            "1STARTS_WITH_DIGIT",
            "DOUBLE__UNDERSCORE",
            "TRAILING_",
            "has space",
            "a=b",
        ] {
            assert!(EnvVarName::parse(bad).is_err(), "{bad}");
        }
        assert_eq!(
            EnvVarName::parse(&"A_".repeat(40)).err(),
            Some(EnvNameError::TooLong)
        );
    }

    #[test]
    fn deserialize_rejects_a_value_with_a_readable_message() {
        let r: Result<EnvVarName, _> = serde_json::from_str("\"sk_live_0123456789abcdef\""); // hdd-secret-scan:allow (test vector)
        let msg = r.err().map(|e| e.to_string()).unwrap_or_default();
        assert!(msg.contains("NAME of an environment variable"), "{msg}");
    }

    #[test]
    fn a_secret_pasted_into_a_path_field_is_not_echoed_as_a_file_name() {
        for pasted in [
            "ghp_0123456789abcdefghijklmnopqrstuvwxyz", // hdd-secret-scan:allow (test vector)
            "sk_live_0123456789abcdef",                 // hdd-secret-scan:allow (test vector)
            "AbCdEfGhIjKlMnOpQrStUvWx0123456789",       // hdd-secret-scan:allow (test vector)
        ] {
            let p = SecretPath::new(pasted);
            assert_eq!(p.to_string(), "…/<redacted>", "{pasted}");
            assert!(!format!("{p:?}").contains("0123456789"));
            assert!(
                !serde_json::to_string(&p)
                    .unwrap_or_default()
                    .contains("0123456789")
            );
        }
        // ordinary file names, with or without a directory, stay readable
        for (path, shown) in [
            ("id_ed25519", "…/id_ed25519"),
            (r"C:\keys\vp.pem", "…/vp.pem"),
            ("/home/op/.ssh/deploy-key-2024", "…/deploy-key-2024"),
        ] {
            assert_eq!(SecretPath::new(path).to_string(), shown, "{path}");
        }
    }

    #[test]
    fn names_that_look_like_random_key_material_are_rejected() {
        for bad in [
            "JBSWY3DP_EHPK3PXP",
            "KRSXG5CTMVRXEZLU_MFRGGZDF",
            "AB12CD34EF56GH78_X",
            "ABCDEFGHIJKLMNOPQ_X",
        ] {
            assert_eq!(
                EnvVarName::parse(bad).err(),
                Some(EnvNameError::LooksLikeCredential),
                "{bad}"
            );
        }
        for ok in [
            "HDD_SMTP_PASSWORD_FILE",
            "AWS_SECRET_ACCESS_KEY",
            "OAUTH2_CLIENT_SECRET",
            "NS1_API_KEY",
            "HDD_BACKUP_SFTP_PRIVATE_KEY",
            "S3_BUCKET_KEY",
            "HDD_MASTER_KEY_PREVIOUS_VERSION",
            "SHA256_SALT",
        ] {
            assert!(EnvVarName::parse(ok).is_ok(), "{ok}");
        }
    }

    #[test]
    fn secret_path_never_prints_the_directory() {
        let p = SecretPath::new("C:\\Users\\op\\.ssh\\id_ed25519");
        assert_eq!(p.file_name(), "id_ed25519");
        assert_eq!(format!("{p}"), "…/id_ed25519");
        assert!(!format!("{p:?}").contains("Users"));
        assert!(
            !serde_json::to_string(&p)
                .unwrap_or_default()
                .contains("ssh\\\\")
        );
        assert_eq!(p.expose_path(), "C:\\Users\\op\\.ssh\\id_ed25519");
        let unix = SecretPath::new("/home/op/.ssh/key");
        assert_eq!(unix.to_string(), "…/key");
        assert_eq!(SecretPath::default().to_string(), "");
    }
}

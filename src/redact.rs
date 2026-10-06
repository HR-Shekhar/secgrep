//! Redact secrets so normal output and JSON cannot leak them.

const KEEP: usize = 4;

pub fn redact(secret: &str) -> String {
    if secret.contains("PRIVATE KEY") {
        return "[REDACTED PRIVATE KEY]".to_string();
    }

    let chars: Vec<char> = secret.chars().collect();
    let n = chars.len();
    if n == 0 {
        return String::new();
    }
    if n <= KEEP {
        return "*".repeat(n);
    }

    let keep_head = KEEP.min(n / 3).max(1);
    let keep_tail = KEEP.min(n / 3).max(1);
    if keep_head + keep_tail >= n {
        return "*".repeat(n);
    }

    let mut out = String::new();
    for ch in &chars[..keep_head] {
        out.push(*ch);
    }
    out.push_str(&"*".repeat(n - keep_head - keep_tail));
    for ch in &chars[n - keep_tail..] {
        out.push(*ch);
    }
    out
}

pub fn fingerprint(secret: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(secret.as_bytes());
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redaction_hides_the_middle() {
        let secret = format!("AKIA{}", "D7K3M2P9Q1W8X4YZ");
        let hidden = redact(&secret);
        assert_ne!(hidden, secret);
        assert!(!hidden.contains("D7K3M2P9"));
        assert!(hidden.contains('*'));
    }

    #[test]
    fn short_secrets_are_fully_masked() {
        assert_eq!(redact("abcd"), "****");
    }

    #[test]
    fn private_keys_are_fully_replaced() {
        let pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIFAKE\n-----END RSA PRIVATE KEY-----";
        assert_eq!(redact(pem), "[REDACTED PRIVATE KEY]");
        assert!(!redact(pem).contains("MIIFAKE"));
    }

    #[test]
    fn fingerprint_is_stable_and_not_the_secret() {
        let secret = format!("AKIA{}", "D7K3M2P9Q1W8X4YZ");
        let fp = fingerprint(&secret);
        assert_eq!(fp.len(), 64);
        assert!(!fp.contains(&secret));
        assert_eq!(fp, fingerprint(&secret));
    }
}

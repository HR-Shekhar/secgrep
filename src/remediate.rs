//! Rotate first. Deleting a line is not remediation.

use crate::finding::Category;

pub fn for_category(category: Category) -> Vec<String> {
    let mut steps = vec![
        "ROTATE/revoke this credential at the provider. Deleting the line does not un-leak it."
            .into(),
        "Remove the literal from source. If it was committed, assume Git history still has it."
            .into(),
        "Check whether the same value exists in Git history (`secgrep history .`).".into(),
        "Review access logs / affected systems for use of this credential.".into(),
        "Document the incident if this was a production secret.".into(),
    ];

    let replacement = match category {
        Category::ApiKey | Category::AccessToken | Category::GenericSecret => {
            vec![
                "Replace with a secret manager or an environment variable (not always enough for production).".into(),
                "Python: os.getenv(\"API_KEY\")  Rust: std::env::var(\"API_KEY\")  Node: process.env.API_KEY".into(),
            ]
        }
        Category::Password => {
            vec![
                "Change the password and stop storing it in Git.".into(),
                "Prefer a secret manager over a raw environment variable for production.".into(),
            ]
        }
        Category::Jwt => {
            vec![
                "If this is a signing secret or a live session token, revoke/rotate it.".into(),
                "Do not commit JWTs or HMAC secrets. Load them at runtime.".into(),
            ]
        }
        Category::PrivateKey => {
            vec![
                "Generate a new key pair. Do not reuse this key material.".into(),
                "Remove the public key from servers/GitHub if it was deployed. Assume the private half is burned.".into(),
            ]
        }
        Category::ConnectionString => {
            vec![
                "Rotate the database/user password embedded in the URL.".into(),
                "Store the URL in a secret manager or platform config, not in source.".into(),
            ]
        }
        Category::AuthorizationHeader => {
            vec![
                "Revoke the bearer token and issue a new one.".into(),
                "Never commit Authorization headers. Inject them at runtime.".into(),
            ]
        }
    };
    steps.splice(2..2, replacement);
    steps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn always_mentions_rotate() {
        for cat in [
            Category::ApiKey,
            Category::PrivateKey,
            Category::ConnectionString,
        ] {
            let text = for_category(cat).join(" ");
            assert!(
                text.contains("ROTATE")
                    || text.contains("Rotate")
                    || text.contains("revoke")
                    || text.contains("Revoke")
            );
        }
    }
}

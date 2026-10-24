//! rvbw_ worker token generation (plan W0). Plaintext exists only at issue time;
//! the store keeps sha256 plus a 4-char prefix for support conversations.
use rand::RngCore;

pub fn generate() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    format!(
        "rvbw_{}",
        base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, bytes)
    )
}
pub fn sha256_hex(token: &str) -> String {
    crate::auth::session::sha256_hex(token)
}
pub fn prefix(token: &str) -> String {
    token.chars().take(9).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tokens_are_unique_prefixed_and_hash_stable() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..10_000 {
            let t = generate();
            assert!(t.starts_with("rvbw_"));
            assert!(seen.insert(t), "10k generations must not collide");
        }
        let t = generate();
        assert_eq!(prefix(&t).len(), 9);
        assert_eq!(sha256_hex(&t), sha256_hex(&t));
        assert_eq!(sha256_hex(&t).len(), 64);
    }
}

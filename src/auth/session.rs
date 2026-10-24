//! rvb_ token generation and hashing (design D4). Plaintext exists only at issue time.
use base64::Engine;
use rand::RngCore;
use sha2::{Digest, Sha256};

pub fn generate() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    format!(
        "rvb_{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    )
}
pub fn sha256_hex(token: &str) -> String {
    hex(&Sha256::digest(token.as_bytes()))
}
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tokens_are_prefixed_unique_and_hash_stable() {
        let a = generate();
        let b = generate();
        assert!(a.starts_with("rvb_") && a.len() >= 44, "{a}"); // rvb_ + >=40 base64url chars
        assert_ne!(a, b);
        assert_eq!(sha256_hex(&a), sha256_hex(&a));
        assert_eq!(sha256_hex(&a).len(), 64);
        assert!(sha256_hex(&a).bytes().all(|x| x.is_ascii_hexdigit()));
    }
}

//! Key derivation and field encryption, byte-compatible with
//! `internal/crypto/crypto.go` of the Go implementation.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

/// Argon2id parameters. Must match the Go implementation exactly.
pub const ARGON2_TIME: u32 = 1;
pub const ARGON2_MEMORY_KIB: u32 = 64 * 1024;
pub const ARGON2_PARALLELISM: u32 = 4;
pub const KEY_LEN: usize = 32;
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;

const VERIFIER_PLAINTEXT: &[u8] = b"verification";

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("key derivation failed: {0}")]
    Kdf(String),
    #[error("ciphertext too short")]
    TooShort,
    #[error("decryption failed")]
    Decrypt,
    #[error("encryption failed")]
    Encrypt,
}

/// 256-bit master key, wiped from memory on drop.
pub type Key = Zeroizing<[u8; KEY_LEN]>;

pub fn derive_key(password: &[u8], salt: &[u8]) -> Result<Key, CryptoError> {
    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_TIME,
        ARGON2_PARALLELISM,
        Some(KEY_LEN),
    )
    .map_err(|e| CryptoError::Kdf(e.to_string()))?;
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password, salt, key.as_mut())
        .map_err(|e| CryptoError::Kdf(e.to_string()))?;
    Ok(key)
}

/// Random data key of a new vault (schema v5).
pub fn generate_key() -> Key {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    rand::fill(key.as_mut());
    key
}

/// Encrypts the data key under the key derived from the password.
pub fn wrap_key(key: &Key, kek: &Key) -> Result<Vec<u8>, CryptoError> {
    encrypt(key.as_slice(), kek)
}

/// Inverse of [`wrap_key`]; fails with a wrong `kek` (wrong password).
pub fn unwrap_key(wrapped: &[u8], kek: &Key) -> Result<Key, CryptoError> {
    let plain = decrypt(wrapped, kek)?;
    if plain.len() != KEY_LEN {
        return Err(CryptoError::Decrypt);
    }
    // Copied straight into zeroized storage, no stray stack copy.
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    key.copy_from_slice(&plain);
    Ok(key)
}

pub fn generate_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    rand::fill(&mut salt);
    salt
}

/// AES-256-GCM; output layout is `nonce(12) || ciphertext || tag(16)`.
pub fn encrypt(plaintext: &[u8], key: &Key) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new((&**key).into());
    let mut nonce = [0u8; NONCE_LEN];
    rand::fill(&mut nonce);
    let ct = cipher
        .encrypt((&nonce).into(), plaintext)
        .map_err(|_| CryptoError::Encrypt)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn decrypt(data: &[u8], key: &Key) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if data.len() < NONCE_LEN {
        return Err(CryptoError::TooShort);
    }
    let (nonce, ct) = data.split_at(NONCE_LEN);
    let cipher = Aes256Gcm::new((&**key).into());
    let nonce = <&Nonce<_>>::try_from(nonce).map_err(|_| CryptoError::TooShort)?;
    cipher
        .decrypt(nonce, ct)
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::Decrypt)
}

pub fn new_verifier(key: &Key) -> Result<Vec<u8>, CryptoError> {
    encrypt(VERIFIER_PLAINTEXT, key)
}

pub fn check_verifier(verifier: &[u8], key: &Key) -> bool {
    decrypt(verifier, key).is_ok_and(|p| p.as_slice() == VERIFIER_PLAINTEXT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let key = derive_key(b"hunter2", &generate_salt()).unwrap();
        let ct = encrypt(b"secret", &key).unwrap();
        assert_eq!(ct.len(), NONCE_LEN + 6 + 16);
        assert_eq!(decrypt(&ct, &key).unwrap().as_slice(), b"secret");
    }

    #[test]
    fn verifier_rejects_wrong_password() {
        let salt = generate_salt();
        let good = derive_key(b"right", &salt).unwrap();
        let bad = derive_key(b"wrong", &salt).unwrap();
        let v = new_verifier(&good).unwrap();
        assert!(check_verifier(&v, &good));
        assert!(!check_verifier(&v, &bad));
    }

    #[test]
    fn key_wrapping() {
        let key = generate_key();
        let kek = derive_key(b"pw", &generate_salt()).unwrap();
        let other = derive_key(b"other", &generate_salt()).unwrap();
        let wrapped = wrap_key(&key, &kek).unwrap();
        assert_eq!(*unwrap_key(&wrapped, &kek).unwrap(), *key);
        assert!(unwrap_key(&wrapped, &other).is_err());
    }

    #[test]
    fn too_short() {
        let key = derive_key(b"x", &generate_salt()).unwrap();
        assert!(matches!(decrypt(&[0; 4], &key), Err(CryptoError::TooShort)));
    }
}

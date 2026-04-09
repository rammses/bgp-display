use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{bail, Context, Result};
use argon2::Argon2;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rand::RngCore;

/// Derive a 32-byte AES key from `passphrase` + `salt_b64`.
pub(crate) fn derive_key(passphrase: &str, salt_b64: &str) -> Result<[u8; 32]> {
    let salt_bytes = B64.decode(salt_b64).context("invalid stored salt")?;
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), &salt_bytes, &mut key)
        .map_err(|e| anyhow::anyhow!("argon2 error: {e}"))?;
    Ok(key)
}

/// Encrypt plaintext → base64(nonce || ciphertext).
pub(crate) fn encrypt(key_bytes: &[u8; 32], plaintext: &str) -> Result<String> {
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| anyhow::anyhow!("encrypt error: {e}"))?;
    let mut blob = nonce_bytes.to_vec();
    blob.extend_from_slice(&ciphertext);
    Ok(B64.encode(blob))
}

/// Decrypt base64(nonce || ciphertext) → plaintext.
pub(crate) fn decrypt(key_bytes: &[u8; 32], b64: &str) -> Result<String> {
    let blob = B64.decode(b64).context("invalid base64 in db")?;
    if blob.len() < 12 {
        bail!("blob too short");
    }
    let (nonce_bytes, ciphertext) = blob.split_at(12);
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);
    let plain = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow::anyhow!("decryption failed — wrong passphrase?"))?;
    String::from_utf8(plain).context("decrypted password not utf-8")
}

use aws_lc_rs::{
    aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey},
    hmac,
    rand::{SecureRandom, SystemRandom},
};
use base64::Engine;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Invalid key length")]
    InvalidKeyLength,
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Decryption failed")]
    DecryptionFailed,
    #[error("Authentication failed")]
    AuthenticationFailed,
    #[error("Invalid data format")]
    InvalidFormat,
    #[error("Random generation failed")]
    RandomFailed,
}

pub struct SessionCrypto {
    rng: SystemRandom,
    hmac_key: hmac::Key,
}

impl SessionCrypto {
    pub fn new(encrypt_key: &[u8], sign_key: &[u8]) -> Result<Self, CryptoError> {
        if encrypt_key.len() != 32 {
            return Err(CryptoError::InvalidKeyLength);
        }
        if sign_key.len() != 32 {
            return Err(CryptoError::InvalidKeyLength);
        }

        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, sign_key);

        Ok(Self {
            rng: SystemRandom::new(),
            hmac_key,
        })
    }

    pub fn generate_keys() -> Result<([u8; 32], [u8; 32]), CryptoError> {
        let rng = SystemRandom::new();
        let mut encrypt_key = [0u8; 32];
        let mut sign_key = [0u8; 32];

        rng.fill(&mut encrypt_key).map_err(|_| CryptoError::RandomFailed)?;
        rng.fill(&mut sign_key).map_err(|_| CryptoError::RandomFailed)?;

        Ok((encrypt_key, sign_key))
    }

    pub fn encrypt(&self, plaintext: &[u8], encrypt_key: &[u8]) -> Result<String, CryptoError> {
        let unbound_key = UnboundKey::new(&AES_256_GCM, encrypt_key).map_err(|_| CryptoError::InvalidKeyLength)?;
        let key = LessSafeKey::new(unbound_key);

        let mut nonce_bytes = [0u8; 12];
        self.rng.fill(&mut nonce_bytes).map_err(|_| CryptoError::RandomFailed)?;

        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        let mut in_out = plaintext.to_vec();
        key.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
            .map_err(|_| CryptoError::EncryptionFailed)?;

        let mut combined = nonce_bytes.to_vec();
        combined.extend_from_slice(&in_out);

        let signature = self.sign(&combined);
        combined.extend_from_slice(signature.as_ref());

        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&combined))
    }

    pub fn decrypt(&self, encoded: &str, decrypt_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let combined = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| CryptoError::InvalidFormat)?;

        if combined.len() < 44 {
            return Err(CryptoError::InvalidFormat);
        }

        let signature_offset = combined.len() - 32;
        let data = &combined[..signature_offset];
        let signature = &combined[signature_offset..];

        if !self.verify(data, signature) {
            return Err(CryptoError::AuthenticationFailed);
        }

        if data.len() < 12 {
            return Err(CryptoError::InvalidFormat);
        }

        let nonce_bytes = &data[..12];
        let ciphertext = &data[12..];

        let unbound_key = UnboundKey::new(&AES_256_GCM, decrypt_key).map_err(|_| CryptoError::InvalidKeyLength)?;
        let key = LessSafeKey::new(unbound_key);

        let nonce = Nonce::assume_unique_for_key(nonce_bytes.try_into().map_err(|_| CryptoError::InvalidFormat)?);

        let mut in_out = ciphertext.to_vec();
        let plaintext = key
            .open_in_place(nonce, Aad::empty(), &mut in_out)
            .map_err(|_| CryptoError::DecryptionFailed)?;

        Ok(plaintext.to_vec())
    }

    fn sign(&self, data: &[u8]) -> hmac::Tag {
        hmac::sign(&self.hmac_key, data)
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> bool {
        hmac::verify(&self.hmac_key, data, signature).is_ok()
    }

    pub fn generate_session_id(&self) -> Result<String, CryptoError> {
        let mut bytes: [u8; 32] = [0u8; 32];
        self.rng.fill(&mut bytes).map_err(|_| CryptoError::RandomFailed)?;
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
    }

    pub fn generate_state(&self) -> Result<String, CryptoError> {
        let mut bytes = [0u8; 16];
        self.rng.fill(&mut bytes).map_err(|_| CryptoError::RandomFailed)?;
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let (encrypt_key, sign_key) = SessionCrypto::generate_keys().unwrap();
        let crypto = SessionCrypto::new(&encrypt_key, &sign_key).unwrap();

        let plaintext = b"secret data";
        let encrypted = crypto.encrypt(plaintext, &encrypt_key).unwrap();
        let decrypted = crypto.decrypt(&encrypted, &encrypt_key).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_tampered_data_fails() {
        let (encrypt_key, sign_key) = SessionCrypto::generate_keys().unwrap();
        let crypto = SessionCrypto::new(&encrypt_key, &sign_key).unwrap();

        let plaintext = b"secret data";
        let mut encrypted = crypto.encrypt(plaintext, &encrypt_key).unwrap();

        encrypted.push('x');

        assert!(crypto.decrypt(&encrypted, &encrypt_key).is_err());
    }
}

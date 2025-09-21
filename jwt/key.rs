use crate::{Algorithm, EcCurve, Error, Jwk, JwkCrypto, OkpCurve, SIGNATURE_MAX_SIZE};
use aws_lc_rs::{
    hmac,
    rand::SystemRandom,
    signature::{
        ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING, ECDSA_P521_SHA512_FIXED,
        ECDSA_P521_SHA512_FIXED_SIGNING, ED25519, EcdsaKeyPair, Ed25519KeyPair, KeyPair,
    },
};

/// a Key used for crypto (sign / verify) operations
pub struct Key {
    pub id: String,
    pub(crate) algorithm: Algorithm,
    pub(crate) crypto: KeyCrypto,
}

pub enum KeyCrypto {
    Eddsa { curve: OkpCurve, keypair: Ed25519KeyPair },
    Ecdsa { curve: EcCurve, keypair: EcdsaKeyPair },
    Hmac { algorithm: HmacAlgorithm, key: Vec<u8> },
}

#[derive(Debug, Clone, Copy)]
pub enum HmacAlgorithm {
    Sha256,
    Sha512,
}

#[derive(Clone, Copy)]
pub struct Signature {
    value: [u8; SIGNATURE_MAX_SIZE],
    length: usize,
}

impl AsRef<[u8]> for Signature {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.value[..self.length]
    }
}

impl From<aws_lc_rs::signature::Signature> for Signature {
    fn from(signature: aws_lc_rs::signature::Signature) -> Self {
        let length = signature.as_ref().len();
        let mut value = [0u8; SIGNATURE_MAX_SIZE];
        value[..length].copy_from_slice(signature.as_ref());

        return Signature { value, length };
    }
}

impl From<aws_lc_rs::hmac::Tag> for Signature {
    fn from(signature: aws_lc_rs::hmac::Tag) -> Self {
        let length = signature.as_ref().len();
        let mut value = [0u8; SIGNATURE_MAX_SIZE];
        value[..length].copy_from_slice(signature.as_ref());

        return Signature { value, length };
    }
}

impl Key {
    pub fn generate_ed25519(id: String) -> Result<Key, Error> {
        let keypair = Ed25519KeyPair::generate()
            .map_err(|err| Error::Unspecified(format!("error generating Ed25519 signing key: {err}")))?;
        return Ok(Key {
            id,
            algorithm: Algorithm::EdDSA,
            crypto: KeyCrypto::Eddsa {
                curve: OkpCurve::Ed25519,
                keypair,
            },
        });
    }

    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    pub fn sign(&self, message: &[u8]) -> Result<Signature, Error> {
        match &self.crypto {
            KeyCrypto::Eddsa { curve: _, keypair } => Ok(keypair.sign(message).into()),
            KeyCrypto::Ecdsa { curve: _, keypair } => keypair
                .sign(&SystemRandom::new(), message)
                .map(Into::into)
                .map_err(|err| Error::Unspecified(format!("error signing token: {err}"))),
            KeyCrypto::Hmac { algorithm, key } => {
                let hmac_key = match algorithm {
                    HmacAlgorithm::Sha256 => hmac::Key::new(hmac::HMAC_SHA256, key),
                    HmacAlgorithm::Sha512 => hmac::Key::new(hmac::HMAC_SHA512, key),
                };
                Ok(hmac::sign(&hmac_key, message).into())
            }
        }
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), Error> {
        match &self.crypto {
            KeyCrypto::Eddsa { curve, keypair } => match curve {
                OkpCurve::Ed25519 => {
                    aws_lc_rs::signature::ParsedPublicKey::new(&ED25519, keypair.public_key().as_ref())
                        .expect("error getting public key")
                        .verify_sig(message, signature)
                        .map_err(|_| Error::InvalidSignature)
                }
            },
            KeyCrypto::Ecdsa { curve, keypair } => match curve {
                EcCurve::P256 => {
                    aws_lc_rs::signature::ParsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, keypair.public_key().as_ref())
                        .expect("error getting public key")
                        .verify_sig(message, signature)
                        .map_err(|_| Error::InvalidSignature)
                }
                EcCurve::P521 => {
                    aws_lc_rs::signature::ParsedPublicKey::new(&ECDSA_P521_SHA512_FIXED, keypair.public_key().as_ref())
                        .expect("error getting public key")
                        .verify_sig(message, signature)
                        .map_err(|_| Error::InvalidSignature)
                }
            },
            KeyCrypto::Hmac { algorithm, key } => {
                let hmac_key = match algorithm {
                    HmacAlgorithm::Sha256 => hmac::Key::new(hmac::HMAC_SHA256, key),
                    HmacAlgorithm::Sha512 => hmac::Key::new(hmac::HMAC_SHA512, key),
                };
                hmac::verify(&hmac_key, message, signature).map_err(|_| Error::InvalidSignature)
            }
        }
    }
}

/// Validate and convert a Jwk to a key
impl TryFrom<Jwk> for Key {
    type Error = Error;

    fn try_from(jwk: Jwk) -> Result<Self, Self::Error> {
        match (jwk.algorithm, jwk.crypto) {
            (Algorithm::HS512, JwkCrypto::Oct { key }) => Ok(Key {
                id: jwk.kid,
                algorithm: jwk.algorithm,
                crypto: KeyCrypto::Hmac {
                    algorithm: HmacAlgorithm::Sha512,
                    key,
                },
            }),
            (Algorithm::EdDSA, JwkCrypto::Okp { curve, x, d }) => {
                let raw_seed = &d.ok_or(Error::InvalidJwk {
                    kid: jwk.kid.clone(),
                    err: "private key is missing".to_string(),
                })?;

                let keypair = match curve {
                    OkpCurve::Ed25519 => {
                        Ed25519KeyPair::from_seed_and_public_key(raw_seed, &x).map_err(|err| Error::InvalidJwk {
                            kid: jwk.kid.clone(),
                            err: err.to_string(),
                        })?
                    }
                };

                Ok(Key {
                    id: jwk.kid,
                    algorithm: Algorithm::EdDSA,
                    crypto: KeyCrypto::Eddsa {
                        curve: OkpCurve::Ed25519,
                        keypair,
                    },
                })
            }
            (Algorithm::ES256, crate::JwkCrypto::Ec { curve, x, y, d })
            | (Algorithm::ES512, crate::JwkCrypto::Ec { curve, x, y, d }) => {
                let private_key = &d.ok_or(Error::InvalidJwk {
                    kid: jwk.kid.clone(),
                    err: "private key is missing".to_string(),
                })?;
                let mut public_key = Vec::with_capacity(1 + x.len() + y.len());
                public_key.push(0x04);
                public_key.extend(y);
                public_key.extend(x);

                let keypair = match curve {
                    EcCurve::P256 => EcdsaKeyPair::from_private_key_and_public_key(
                        &ECDSA_P256_SHA256_FIXED_SIGNING,
                        private_key,
                        &public_key,
                    ),
                    EcCurve::P521 => EcdsaKeyPair::from_private_key_and_public_key(
                        &ECDSA_P521_SHA512_FIXED_SIGNING,
                        private_key,
                        &public_key,
                    ),
                }
                .map_err(|err| Error::InvalidJwk {
                    kid: jwk.kid.clone(),
                    err: err.to_string(),
                })?;

                Ok(Key {
                    id: jwk.kid,
                    algorithm: jwk.algorithm,
                    crypto: KeyCrypto::Ecdsa { curve, keypair },
                })
            }
            _ => {
                return Err(Error::InvalidJwk {
                    kid: jwk.kid,
                    err: "JWK is not valid".to_string(),
                });
            }
        }
    }
}

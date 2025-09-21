use crate::{EcCurve, Error, Jwk, OkpCurve};
use aws_lc_rs::{
    rand::SystemRandom,
    signature::{
        ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING, ECDSA_P521_SHA512_FIXED,
        ECDSA_P521_SHA512_FIXED_SIGNING, ED25519, EcdsaKeyPair, Ed25519KeyPair, KeyPair,
    },
};

/// a Key used for crypto (sign / verify) operations
#[derive(Debug)]
pub struct Key {
    pub id: String,
    pub(crate) crypto: KeyCrypto,
}

#[derive(Debug)]
pub enum KeyCrypto {
    Eddsa { curve: OkpCurve, keypair: Ed25519KeyPair },
    Ecdsa { curve: EcCurve, keypair: EcdsaKeyPair },
}

pub struct Signature(aws_lc_rs::signature::Signature);

impl AsRef<[u8]> for Signature {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl From<aws_lc_rs::signature::Signature> for Signature {
    fn from(signature: aws_lc_rs::signature::Signature) -> Self {
        return Signature(signature);
    }
}

impl Key {
    pub fn new_ed25519(id: String) -> Result<Key, Error> {
        let keypair = Ed25519KeyPair::generate()
            .map_err(|err| Error::Unspecified(format!("error generating Ed25519 signing key: {err}")))?;
        return Ok(Key {
            id,
            crypto: KeyCrypto::Eddsa {
                curve: OkpCurve::Ed25519,
                keypair,
            },
        });
    }

    pub fn sign(&self, message: &[u8]) -> Result<Signature, Error> {
        match &self.crypto {
            KeyCrypto::Eddsa { curve: _, keypair } => Ok(keypair.sign(message).into()),
            KeyCrypto::Ecdsa { curve: _, keypair } => keypair
                .sign(&SystemRandom::new(), message)
                .map(|signature| signature.into())
                .map_err(|err| Error::Unspecified(format!("error signing token: {err}"))),
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
        }
    }
}

impl TryFrom<Jwk> for Key {
    type Error = Error;

    fn try_from(jwk: Jwk) -> Result<Self, Self::Error> {
        match jwk.crypto {
            crate::JwkCrypto::Okp { curve, x, d } => {
                let raw_seed = &d
                    .ok_or(Error::InvalidJwk {
                        kid: jwk.kid.clone(),
                        err: "private key is missing".to_string(),
                    })?
                    .0;

                let keypair = match curve {
                    OkpCurve::Ed25519 => {
                        Ed25519KeyPair::from_seed_and_public_key(raw_seed, &x.0).map_err(|err| Error::InvalidJwk {
                            kid: jwk.kid.clone(),
                            err: err.to_string(),
                        })?
                    }
                };

                Ok(Key {
                    id: jwk.kid,
                    crypto: KeyCrypto::Eddsa { curve, keypair },
                })
            }
            crate::JwkCrypto::Ec { curve, x, y, d } => {
                let private_key = &d
                    .ok_or(Error::InvalidJwk {
                        kid: jwk.kid.clone(),
                        err: "private key is missing".to_string(),
                    })?
                    .0;
                let mut public_key = Vec::with_capacity(1 + x.0.len() + y.0.len());
                public_key.push(0x04);
                public_key.extend(x.0);
                public_key.extend(y.0);

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
                    crypto: KeyCrypto::Ecdsa { curve, keypair },
                })
            }
        }
    }
}

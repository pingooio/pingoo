use aws_lc_rs::{
    encoding::AsBigEndian,
    signature::{Ed25519KeyPair, KeyPair},
};

use crate::Error;

pub struct JwtKey {
    pub id: String,
    pub private_key: Ed25519KeyPair,
}

pub fn convert_key_to_jwk(key: &JwtKey) -> jwt::Jwk {
    let seed = key.private_key.seed().expect("error getting Ed25519 key seed");
    let private_key = seed
        .as_be_bytes()
        .expect("error getting Ed25519 private key")
        .as_ref()
        .to_vec();
    let public_key = key.private_key.public_key().as_ref().to_vec();

    return jwt::Jwk {
        kid: key.id.clone(),
        kty: jwt::KeyType::OKP,
        r#use: jwt::KeyUse::Sign,
        alg: jwt::Algorithm::EdDSA,
        crv: jwt::EllipticCurve::Ed25519,
        x: public_key.into(),
        d: Some(private_key.into()),
    };
}

pub fn convert_jwk_to_key(jwk: jwt::Jwk) -> Result<JwtKey, Error> {
    let raw_seed = jwk
        .d
        .ok_or(Error::Unspecified(format!("private_key is missing from JWK ({})", &jwk.kid)))?
        .0;
    let private_key = Ed25519KeyPair::from_seed_and_public_key(&raw_seed, &jwk.x.0)
        .map_err(|err| Error::Unspecified(format!("JWK ({}) is not a valid Ed25519 key: {err}", &jwk.kid)))?;

    return Ok(JwtKey {
        id: jwk.kid,
        private_key,
    });
}

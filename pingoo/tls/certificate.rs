use std::{
    io::{self, BufReader},
    sync::Arc,
};

use aws_lc_rs::digest::{SHA256, digest};
use chrono::{DateTime, Datelike, TimeZone, Utc};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};
use rustls::{crypto::CryptoProvider, pki_types::CertificateDer, sign::CertifiedKey};
use wildcard::{Wildcard, WildcardBuilder};
use x509_parser::prelude::{FromDer, GeneralName, ParsedExtension, X509Certificate};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::Error;

#[derive(Clone, Debug)]
pub struct Certificate {
    /// Both the private key and public certificate.
    /// In rustls terms, it's actually a cert resolver.
    pub key: Arc<CertifiedKey>,
    pub metadata: CertificateMetadata,
}

#[derive(Clone, Debug)]
pub struct CertificateMetadata {
    /// hash of the DER encoding of the certificate / key
    pub hash: [u8; 32],
    /// hash of the DER encoding of the private key
    pub private_key_hash: [u8; 32],
    pub hostnames: Vec<String>,
    pub wildcard_matchers: Vec<Wildcard<'static>>,
    pub not_after: DateTime<Utc>,
    pub not_before: DateTime<Utc>,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PrivateKeyAndCertPem {
    pub key: String,
    pub cert: String,
}

pub fn parse_certificate_and_private_key(
    certs_pem: &[u8],
    private_key_pem: &[u8],
    crypto_provider: &CryptoProvider,
) -> Result<Certificate, Error> {
    let private_key = rustls_pemfile::private_key(&mut BufReader::new(private_key_pem))
        .map_err(|err| Error::Config(format!("error parsing TLS private key: {err}")))?
        .ok_or(Error::Tls("private key file is not valid".to_string()))?;

    let certificates: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut BufReader::new(certs_pem))
        .collect::<io::Result<_>>()
        .map_err(|err| Error::Config(format!("error parsing TLS certificates: {err}")))?;
    if certificates.is_empty() {
        return Err(Error::Tls("TLS cert chain is empty".to_string()));
    }
    // TODO: is the server certificate always the first one in a chain?
    let cert_metdata = get_certificate_metdata(&certificates[0], private_key.secret_der())?;
    if cert_metdata.hostnames.is_empty() && cert_metdata.wildcard_matchers.is_empty() {
        return Err(Error::Tls(
            "TLS certificate is not valid: hostnames list (SAN, Subject Alternative Name) is empty".to_string(),
        ));
    }

    let certified_key = CertifiedKey::from_der(certificates, private_key, crypto_provider)
        .map_err(|err| Error::Tls(format!("error verifying TLS certificates: {err}")))?;

    return Ok(Certificate {
        key: Arc::new(certified_key),
        metadata: cert_metdata,
    });
}

fn get_certificate_metdata(cert_der: &[u8], private_key_der: &[u8]) -> Result<CertificateMetadata, Error> {
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|err| Error::Tls(format!("error parsing TLS certificate: {err}")))?;

    // validity
    let not_before = Utc
        .timestamp_opt(cert.validity.not_before.timestamp(), 0)
        .single()
        .ok_or(Error::Tls(format!(
            "TLS certificate not_before timestamp ({}) is not valid",
            cert.validity.not_before.timestamp()
        )))?;
    let not_after = Utc
        .timestamp_opt(cert.validity.not_after.timestamp(), 0)
        .single()
        .ok_or(Error::Tls(format!(
            "TLS certificate not_after timestamp ({}) is not valid",
            cert.validity.not_after.timestamp()
        )))?;

    // hostnames
    let mut subject_alternative_names = Vec::new();
    for ext in cert.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = &ext.parsed_extension() {
            for name in san.general_names.iter() {
                match name {
                    GeneralName::DNSName(d) => subject_alternative_names.push(d.to_string()),
                    GeneralName::IPAddress(bytes) => {
                        let ip = if bytes.len() == 4 {
                            std::net::IpAddr::from(<[u8; 4]>::try_from(&bytes[..4]).unwrap())
                        } else if bytes.len() == 16 {
                            std::net::IpAddr::from(<[u8; 16]>::try_from(&bytes[..16]).unwrap())
                        } else {
                            continue;
                        };
                        subject_alternative_names.push(ip.to_string());
                    }
                    _ => {}
                }
            }
        }
    }

    let wildcard_matchers = subject_alternative_names
        .iter()
        .filter(|hostname| hostname.contains('*'))
        .map(|hostname| {
            let matcher = WildcardBuilder::from_owned(hostname.clone().into_bytes())
                .case_insensitive(false)
                .without_one_metasymbol()
                .build()
                .map_err(|err| Error::Tls(format!("TLS hostname {hostname} is not valid: {err}")))?;

            Ok(matcher)
        })
        .collect::<Result<_, Error>>()?;

    let hostnames = subject_alternative_names
        .into_iter()
        .filter(|san| !san.contains('*'))
        .collect();

    return Ok(CertificateMetadata {
        hash: digest(&SHA256, cert_der).as_ref().try_into().unwrap(),
        private_key_hash: digest(&SHA256, private_key_der).as_ref().try_into().unwrap(),
        hostnames,
        wildcard_matchers,
        not_after,
        not_before,
    });
}

pub fn generate_self_signed_certificates(hostnames: &[&str]) -> Result<(Certificate, PrivateKeyAndCertPem), Error> {
    let now = Utc::now();
    let mut cert_params: CertificateParams = Default::default();
    // 1 year validaity by default
    cert_params.not_before = rcgen::date_time_ymd(now.year(), now.month() as u8, now.day() as u8);
    cert_params.not_after = rcgen::date_time_ymd(now.year() + 1, now.month() as u8, now.day() as u8);

    // TODO
    cert_params.distinguished_name = DistinguishedName::new();
    cert_params
        .distinguished_name
        .push(DnType::CommonName, "Pingoo self-signed certificate");

    cert_params.subject_alt_names = hostnames
        .iter()
        .map(|hostname| {
            Ok(SanType::DnsName(hostname.to_string().try_into().map_err(|err| {
                Error::Tls(format!("error converting hostname {hostname} to SAN name: {err}"))
            })?))
        })
        .collect::<Result<_, Error>>()?;

    let key_pair = KeyPair::generate()
        .map_err(|err| Error::Tls(format!("error generating keypair for self-signed certificate: {err}")))?;

    // it seems to be okay to sign self-signed certificate with the server's private key
    let cert = cert_params
        .self_signed(&key_pair)
        .map_err(|err| Error::Tls(format!("error seigning self-signed certificate: {err}")))?;

    let cert_pem = cert.pem();
    let private_key_pem = key_pair.serialize_pem();

    let certificate = parse_certificate_and_private_key(
        cert_pem.as_bytes(),
        private_key_pem.as_bytes(),
        CryptoProvider::get_default().unwrap(),
    )?;

    return Ok((
        certificate,
        PrivateKeyAndCertPem {
            key: private_key_pem,
            cert: cert_pem,
        },
    ));
}

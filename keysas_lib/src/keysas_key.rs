// SPDX-License-Identifier: GPL-3.0-only
/*
 * The "keysas-lib".
 *
 * (C) Copyright 2019-2023 Stephane Neveu, Luc Bonnafoux
 *
 * This file contains various funtions
 * for building the keysas_lib.
 */

#![warn(unused_extern_crates)]
#![forbid(non_shorthand_field_patterns)]
#![warn(dead_code)]
#![warn(missing_debug_implementations)]
#![warn(missing_copy_implementations)]
#![warn(trivial_casts)]
#![warn(trivial_numeric_casts)]
#![warn(unused_extern_crates)]
#![warn(unused_import_braces)]
#![warn(unused_qualifications)]
#![warn(variant_size_differences)]
#![forbid(private_in_public)]
#![warn(overflowing_literals)]
#![warn(deprecated)]
#![warn(unused_imports)]

use anyhow::{anyhow, Context};
use der::DecodePem;
use ed25519_dalek::Digest;
use ed25519_dalek::Keypair;
use ed25519_dalek::PublicKey;
use ed25519_dalek::Sha512;
use ed25519_dalek::Signature as SignatureDalek;
use ed25519_dalek::Signer;
use ed25519_dalek::Verifier;
use oqs::sig::Algorithm;
use oqs::sig::PublicKey as PqPublicKey;
use oqs::sig::SecretKey;
use oqs::sig::Sig;
use oqs::sig::Signature as SignatureOqs;
use pkcs8::der::asn1::SetOfVec;
use pkcs8::pkcs5::pbes2;
use pkcs8::EncryptedPrivateKeyInfo;
use pkcs8::PrivateKeyInfo;
use rand_dl::rngs::OsRng;
use rand_dl::RngCore;
use std::fs;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use x509_cert::certificate::*;
use x509_cert::der::asn1::BitString;
use x509_cert::der::Encode;
use x509_cert::name::RdnSequence;
use x509_cert::request::CertReq;
use x509_cert::request::CertReqInfo;
use x509_cert::spki::AlgorithmIdentifier;
use x509_cert::spki::ObjectIdentifier;
use x509_cert::spki::SubjectPublicKeyInfo;

use crate::certificate_field::CertificateFields;
use crate::pki::DILITHIUM5_OID;
use crate::pki::ED25519_OID;

#[derive(Debug)]
pub struct KeysasPQKey {
    pub private_key: SecretKey,
    pub public_key: oqs::sig::PublicKey,
}

#[derive(Debug)]
pub struct KeysasHybridPubKeys {
    pub classic: PublicKey,
    pub pq: PqPublicKey,
}

#[derive(Debug)]
pub struct KeysasHybridSignature {
    pub classic: SignatureDalek,
    pub pq: SignatureOqs,
}
pub trait PublicKeys<T> {
    fn get_pubkeys_from_certs(
        path_cl: &str,
        path_pq: &str,
    ) -> Result<Option<KeysasHybridPubKeys>, anyhow::Error>;
    fn verify_key_signatures(
        message: &[u8],
        signatures: KeysasHybridSignature,
        pubkeys: KeysasHybridPubKeys,
    ) -> Result<(), anyhow::Error>;
}

impl PublicKeys<KeysasHybridPubKeys> for KeysasHybridPubKeys {
    fn get_pubkeys_from_certs(
        cert_cl: &str,
        cert_pq: &str,
    ) -> Result<Option<KeysasHybridPubKeys>, anyhow::Error> {
        let mut cert_cl = File::open(cert_cl)
            .context("Cannot open Classic PEM certificate to get the public key")?;
        let mut cert_cl_bytes = Vec::new();
        cert_cl
            .read_to_end(&mut cert_cl_bytes)
            .context("Cannot read Classic certificate file.")?;
        let mut cert_pq = File::open(cert_pq)
            .context("Cannot open Dilithium PEM certificate to get the public key")?;
        let mut cert_pq_bytes = Vec::new();
        cert_pq
            .read_to_end(&mut cert_pq_bytes)
            .context("Cannot read Dilithium certificate file")?;
        let cert_cl = Certificate::from_pem(cert_cl_bytes)?;
        let cert_pq = Certificate::from_pem(cert_pq_bytes)?;

        let pub_cl = ed25519_dalek::PublicKey::from_bytes(
            cert_cl
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .raw_bytes(),
        )?;
        oqs::init();
        let pq_scheme = match Sig::new(Algorithm::Dilithium5) {
            Ok(pq_s) => pq_s,
            Err(e) => return Err(anyhow!("Cannot construct Dilithium algorithm: {e}")),
        };
        let pub_pq = match pq_scheme.public_key_from_bytes(
            cert_pq
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .raw_bytes(),
        ) {
            Some(pk) => pk,
            None => return Ok(None),
        };

        Ok(Some(KeysasHybridPubKeys {
            classic: pub_cl,
            pq: pub_pq.to_owned(),
        }))
    }
    fn verify_key_signatures(
        message: &[u8],
        signatures: KeysasHybridSignature,
        pubkeys: KeysasHybridPubKeys,
    ) -> Result<(), anyhow::Error> {
        pubkeys
            .classic
            .verify(message, &signatures.classic)
            .context("Invalid Ed25519 signature")?;
        oqs::init();
        let pq_scheme = match Sig::new(Algorithm::Dilithium5) {
            Ok(pq_s) => pq_s,
            Err(e) => return Err(anyhow!("Cannot construct new Dilithium algorithm: {e}")),
        };
        match pq_scheme.verify(message, &signatures.pq, &pubkeys.pq) {
            Ok(_) => log::info!("Dilithium scheme is verified"),
            Err(e) => return Err(anyhow!("Dilithium scheme is not verified: {e}")),
        };
        // If no error has been returned then the signature is valid
        Ok(())
    }
}

/// Store a keypair in a PKCS8 file with a password
fn store_keypair(
    prk: &[u8],
    pbk: &[u8],
    oid: ObjectIdentifier,
    pwd: &str,
    path: &Path,
) -> Result<(), anyhow::Error> {
    //Initialize key wrap function parameters
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let mut iv = [0u8; 16];
    OsRng.fill_bytes(&mut iv);
    // Use default parameters for scrypt
    let params = match pbes2::Parameters::scrypt_aes256cbc(
        pkcs8::pkcs5::scrypt::Params::recommended(),
        &salt,
        &iv,
    ) {
        Ok(p) => p,
        Err(e) => {
            return Err(anyhow!("Failed to generate scrypt parameter: {e}"));
        }
    };

    let pk_info = PrivateKeyInfo {
        algorithm: pkcs8::AlgorithmIdentifierRef {
            oid,
            parameters: None,
        },
        private_key: prk,
        public_key: Some(pbk),
    };

    let pk_encrypted = match pk_info.encrypt_with_params(params, pwd) {
        Ok(pk) => pk,
        Err(e) => {
            log::error!("Failed to encrypt private key: {e}");
            return Err(anyhow!("Failed to encrypt private key"));
        }
    };

    pk_encrypted.write_der_file(path)?;

    Ok(())
}

/// Generic trait to abstract the main functions of the ED25519 and Dilthium keys
pub trait KeysasKey<T> {
    /// Generate a new key pair
    fn generate_new() -> Result<T, anyhow::Error>;
    /// Load keypair from a DER encoded PKCS8 file protected with a password
    fn load_keys(path: &Path, pwd: &str) -> Result<T, anyhow::Error>;
    /// Save keypair in a DER encoded PKCS8 file protected with a password
    fn save_keys(&self, path: &Path, pwd: &str) -> Result<(), anyhow::Error>;
    /// Generate a Certificate Signing Request for the keypair and with the subject name
    fn generate_csr(&self, subject: &RdnSequence) -> Result<CertReq, anyhow::Error>;
    /// Sign a message
    fn message_sign(&self, message: &[u8]) -> Result<Vec<u8>, anyhow::Error>;
    /// Verify the signature of a message
    fn message_verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, anyhow::Error>;
    /// Generate a certificate from a CSR and signed with the key
    fn generate_certificate(
        &self,
        ca_infos: &CertificateFields,
        subject_infos: &RdnSequence,
        subject_key: &[u8],
        serial: &[u8; 20],
        is_app_cert: bool,
    ) -> Result<Certificate, anyhow::Error>;
}

// Implementing new methods on top of dalek Keypair
impl KeysasKey<Keypair> for Keypair {
    fn generate_new() -> Result<Keypair, anyhow::Error> {
        let mut csprng = OsRng {};
        let kp_ed = Keypair::generate(&mut csprng);
        Ok(kp_ed)
    }

    fn load_keys(path: &Path, pwd: &str) -> Result<Keypair, anyhow::Error> {
        // Load the pkcs8 from file
        let cipher = fs::read(path)?;

        let enc_pk = match EncryptedPrivateKeyInfo::try_from(cipher.as_slice()) {
            Ok(ep) => ep,
            Err(e) => {
                return Err(anyhow!("Failed to parse EncryptedPrivateKeyInfo: {e}"));
            }
        };
        let pk = match enc_pk.decrypt(pwd) {
            Ok(p) => p,
            Err(e) => {
                return Err(anyhow!("Failed to decrypt document: {e}"));
            }
        };
        let decoded_pk: PrivateKeyInfo = match pk.decode_msg() {
            Ok(parsed_pk) => parsed_pk,
            Err(e) => {
                return Err(anyhow!(
                    "Failed to decode asn.1 format for private key: {e}"
                ));
            }
        };
        // ed25519 is only 32 bytes long
        if decoded_pk.private_key.len() == 32 {
            match ed25519_dalek::SecretKey::from_bytes(decoded_pk.private_key) {
                Ok(secret_key) => Ok(Keypair {
                    public: (&(secret_key)).into(),
                    secret: secret_key,
                }),
                Err(e) => Err(anyhow!(
                    "Cannot parse private key CLASSIC/ed25519-dalek from pkcs#8: {e}"
                )),
            }
        } else {
            Err(anyhow!("Key is not 32 bytes long"))
        }
    }

    fn save_keys(&self, path: &Path, pwd: &str) -> Result<(), anyhow::Error> {
        let ed25519_oid = ObjectIdentifier::new(ED25519_OID)?;

        store_keypair(
            self.secret.as_bytes(),
            self.public.as_bytes(),
            ed25519_oid,
            pwd,
            path,
        )
    }

    fn generate_csr(&self, subject: &RdnSequence) -> Result<CertReq, anyhow::Error> {
        let ed25519_oid = ObjectIdentifier::new(ED25519_OID)?;

        let pub_key = BitString::from_bytes(&self.public.to_bytes())
            .with_context(|| "Failed get public key raw value")?;

        let info = CertReqInfo {
            version: x509_cert::request::Version::V1,
            subject: subject.to_owned(),
            public_key: SubjectPublicKeyInfo {
                algorithm: AlgorithmIdentifier {
                    oid: ed25519_oid,
                    parameters: None,
                },
                subject_public_key: pub_key,
            },
            attributes: SetOfVec::new(),
        };

        let content = info.to_der().with_context(|| "Failed to convert to DER")?;
        let mut prehashed = Sha512::new();
        prehashed.update(content);
        let signature = self
            .sign_prehashed(prehashed, None)
            .with_context(|| "Failed to sign certificate content")?;

        let csr = CertReq {
            info,
            algorithm: AlgorithmIdentifier {
                oid: ed25519_oid,
                parameters: None,
            },
            signature: BitString::from_bytes(&signature.to_bytes())?,
        };

        Ok(csr)
    }

    fn message_sign(&self, message: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        let signature = self.sign(message);
        Ok(signature.to_bytes().to_vec())
    }

    fn message_verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, anyhow::Error> {
        let sig = ed25519_dalek::Signature::from_bytes(signature)?;
        self.verify(message, &sig)?;
        // If no error has been returned then the signature is valid
        Ok(true)
    }

    fn generate_certificate(
        &self,
        ca_infos: &CertificateFields,
        subject_infos: &RdnSequence,
        subject_key: &[u8],
        serial: &[u8; 20],
        is_app_cert: bool,
    ) -> Result<Certificate, anyhow::Error> {
        let ed25519_oid = ObjectIdentifier::new(ED25519_OID)?;

        // Build the certificate
        let tbs = ca_infos.construct_tbs_certificate(
            subject_infos,
            subject_key,
            serial,
            &ed25519_oid,
            is_app_cert,
        )?;

        let content = tbs.to_der().with_context(|| "Failed to convert to DER")?;
        let mut prehashed = Sha512::new();
        prehashed.update(content);
        let signature = self
            .sign_prehashed(prehashed, None)
            .with_context(|| "Failed to sign certificate content")?;

        let cert = Certificate {
            tbs_certificate: tbs,
            signature_algorithm: AlgorithmIdentifier {
                oid: ed25519_oid,
                parameters: None,
            },
            signature: BitString::from_bytes(&signature.to_bytes())?,
        };
        Ok(cert)
    }
}

impl KeysasKey<KeysasPQKey> for KeysasPQKey {
    fn generate_new() -> Result<KeysasPQKey, anyhow::Error> {
        // Important load oqs:
        oqs::init();

        let pq_scheme = match Sig::new(Algorithm::Dilithium5) {
            Ok(pq_s) => pq_s,
            Err(e) => return Err(anyhow!("Cannot construct new Dilithium algorithm: {e}")),
        };
        let (pk_dl, sk_dl) = match pq_scheme.keypair() {
            Ok((public, secret)) => (public, secret),
            Err(e) => return Err(anyhow!("Cannot generate new Dilithium keypair: {e}")),
        };
        let kp_pq = KeysasPQKey {
            private_key: sk_dl,
            public_key: pk_dl,
        };
        Ok(kp_pq)
    }

    fn load_keys(path: &Path, pwd: &str) -> Result<KeysasPQKey, anyhow::Error> {
        // Important load oqs:
        oqs::init();

        // Load the pkcs8 from file
        let cipher = fs::read(path)?;
        log::debug!("Read done: {path:?}");

        let enc_pk = match EncryptedPrivateKeyInfo::try_from(cipher.as_slice()) {
            Ok(ep) => ep,
            Err(e) => {
                return Err(anyhow!("Failed to parse EncryptedPrivateKeyInfo: {e}"));
            }
        };
        let pk = match enc_pk.decrypt(pwd) {
            Ok(p) => p,
            Err(e) => {
                return Err(anyhow!("Failed to decrypt document: {e}"));
            }
        };
        let decoded_pk: PrivateKeyInfo = match pk.decode_msg() {
            Ok(parsed_pk) => parsed_pk,
            Err(e) => {
                return Err(anyhow!(
                    "Failed to decode asn.1 format for private key: {e}"
                ));
            }
        };
        oqs::init();
        let scheme = match oqs::sig::Sig::new(oqs::sig::Algorithm::Dilithium5) {
            Ok(scheme) => scheme,
            Err(e) => {
                return Err(anyhow!(
                    "OQS error: cannot initialize Dililthium5 scheme: {e}"
                ))
            }
        };
        let tmp_pq_sk = match oqs::sig::Sig::secret_key_from_bytes(&scheme, decoded_pk.private_key)
        {
            Some(tmp_sig_sk) => tmp_sig_sk,
            None => {
                return Err(anyhow!(
                    "Cannot parse secret pq private key from decode value"
                ));
            }
        };
        let secret_key = tmp_pq_sk.to_owned();
        match decoded_pk.public_key {
            Some(public_key_u8) => {
                let public_key = match oqs::sig::Sig::public_key_from_bytes(&scheme, public_key_u8)
                {
                    Some(p) => p,
                    None => {
                        return Err(anyhow!("Cannot parse PQC public key from pkcs#8"));
                    }
                };
                Ok(KeysasPQKey {
                    private_key: secret_key,
                    public_key: public_key.to_owned(),
                })
            }
            None => Err(anyhow!("No PQC public key found in pkcs#8 format")),
        }
    }

    fn save_keys(&self, path: &Path, pwd: &str) -> Result<(), anyhow::Error> {
        let ed25519_oid = ObjectIdentifier::new(ED25519_OID)?;

        store_keypair(
            &self.private_key.clone().into_vec(),
            &self.public_key.clone().into_vec(),
            ed25519_oid,
            pwd,
            path,
        )
    }

    fn generate_csr(&self, subject: &RdnSequence) -> Result<CertReq, anyhow::Error> {
        // Important load oqs:
        oqs::init();

        let dilithium5_oid = ObjectIdentifier::new(DILITHIUM5_OID)?;

        let pub_key = BitString::from_bytes(&self.public_key.clone().into_vec())
            .with_context(|| "Failed get public key raw value")?;

        let info = CertReqInfo {
            version: x509_cert::request::Version::V1,
            subject: subject.to_owned(),
            public_key: SubjectPublicKeyInfo {
                algorithm: AlgorithmIdentifier {
                    oid: dilithium5_oid,
                    parameters: None,
                },
                subject_public_key: pub_key,
            },
            attributes: SetOfVec::new(),
        };

        let content = info.to_der().with_context(|| "Failed to convert to DER")?;
        let pq_scheme = match Sig::new(Algorithm::Dilithium5) {
            Ok(pq_s) => pq_s,
            Err(e) => return Err(anyhow!("Cannot construct new Dilithium algorithm: {e}")),
        };
        let signature = match pq_scheme.sign(&content, &self.private_key) {
            Ok(sig) => sig,
            Err(e) => return Err(anyhow!("Cannot sign message: {e}")),
        };

        let csr = CertReq {
            info,
            algorithm: AlgorithmIdentifier {
                oid: dilithium5_oid,
                parameters: None,
            },
            signature: BitString::from_bytes(&signature.into_vec())?,
        };

        Ok(csr)
    }

    fn message_sign(&self, message: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        oqs::init();
        let pq_scheme = match Sig::new(Algorithm::Dilithium5) {
            Ok(pq_s) => pq_s,
            Err(e) => return Err(anyhow!("Cannot construct new Dilithium algorithm: {e}")),
        };
        let signature = match pq_scheme.sign(message, &self.private_key) {
            Ok(sig) => sig,
            Err(e) => return Err(anyhow!("Cannot sign message: {e}")),
        };
        Ok(signature.into_vec())
    }

    fn message_verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, anyhow::Error> {
        oqs::init();
        let pq_scheme = match Sig::new(Algorithm::Dilithium5) {
            Ok(pq_s) => pq_s,
            Err(e) => return Err(anyhow!("Cannot construct new Dilithium algorithm: {e}")),
        };
        let sig = match pq_scheme.signature_from_bytes(signature) {
            Some(s) => s,
            None => {
                return Err(anyhow!("Invalid signature input"));
            }
        };
        match pq_scheme.verify(message, sig, &self.public_key) {
            Ok(_) => log::info!("Dilithium scheme verified"),
            Err(e) => return Err(anyhow!("Dilithium scheme not verified: {e}")),
        }
        // If no error then the signature is valid
        Ok(true)
    }

    fn generate_certificate(
        &self,
        ca_infos: &CertificateFields,
        subject_infos: &RdnSequence,
        subject_key: &[u8],
        serial: &[u8; 20],
        is_app_cert: bool,
    ) -> Result<Certificate, anyhow::Error> {
        // Important load oqs:
        oqs::init();

        let dilithium5_oid = ObjectIdentifier::new(DILITHIUM5_OID)?;

        // Build the certificate
        let tbs = ca_infos.construct_tbs_certificate(
            subject_infos,
            subject_key,
            serial,
            &dilithium5_oid,
            is_app_cert,
        )?;

        let content = tbs.to_der().with_context(|| "Failed to convert to DER")?;

        let pq_scheme = match Sig::new(Algorithm::Dilithium5) {
            Ok(pq_s) => pq_s,
            Err(e) => return Err(anyhow!("Cannot construct new Dilithium algorithm: {e}")),
        };
        let signature = match pq_scheme.sign(&content, &self.private_key) {
            Ok(sig) => sig,
            Err(e) => return Err(anyhow!("Cannot sign message: {e}")),
        };

        let cert = Certificate {
            tbs_certificate: tbs,
            signature_algorithm: AlgorithmIdentifier {
                oid: dilithium5_oid,
                parameters: None,
            },
            signature: BitString::from_bytes(&signature.into_vec())?,
        };
        Ok(cert)
    }
}

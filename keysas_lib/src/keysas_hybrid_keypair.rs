// SPDX-License-Identifier: GPL-3.0-only
/*
 * The "keysas-lib".
 *
 * (C) Copyright 2019-2025 Stephane Neveu, Luc Bonnafoux
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
#![warn(unused_import_braces)]
#![warn(unused_qualifications)]
#![warn(variant_size_differences)]
#![forbid(trivial_bounds)]
#![warn(overflowing_literals)]
#![warn(deprecated)]
#![warn(unused_imports)]

use anyhow::Context;
use anyhow::anyhow;
use ed25519_dalek::Signer;
use ed25519_dalek::SigningKey;
use oqs::sig::Algorithm;
use oqs::sig::SecretKey;
use oqs::sig::Sig;
use pkcs8::LineEnding;
use pkcs8::der::DecodePem;
use pkcs8::der::Encode;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use x509_cert::certificate::Certificate;
use x509_cert::der::EncodePem;
use x509_cert::der::asn1::BitString;
use x509_cert::name::RdnSequence;
use x509_cert::spki::AlgorithmIdentifier;
use x509_cert::spki::ObjectIdentifier;

use crate::certificate_field::CertificateFields;
use crate::keysas_key::KeysasKey;
use crate::keysas_key::KeysasPQKey;
use crate::pki::ED25519_OID;
use crate::pki::ML_DSA87_OID;
use crate::pki::generate_cert_from_csr;

/// Keysas `HybridKeyPair`
///
/// Structure containing both a ED25519 and a ML-DSA87 keypair
/// The structure also contains the associated certificates
#[derive(Debug)]
pub struct HybridKeyPair {
    pub classic: SigningKey,
    pub classic_cert: Certificate,
    pub pq: KeysasPQKey,
    pub pq_cert: Certificate,
}

/// Generate the root certificate of the PKI from a private key and information
/// fields
/// The function returns the certificate or an openssl error
fn generate_root_ed25519(
    infos: &CertificateFields,
) -> Result<(SigningKey, Certificate), anyhow::Error> {
    // Create the root CA Ed25519 key pair
    let keypair: SigningKey = SigningKey::generate_new()?;
    let ed25519_oid =
        ObjectIdentifier::new(ED25519_OID).with_context(|| "Failed to generate OID")?;

    // Root ED25519 certificate will have serial number
    let serial: [u8; 20] = [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1];

    // Build subject DN
    let subject = infos.generate_dn()?;

    let tbs = infos.construct_tbs_certificate(
        &subject,
        &keypair.verifying_key().to_bytes(),
        &serial,
        &ed25519_oid,
        true,
    )?;

    let content = tbs.to_der().with_context(|| "Failed to convert to DER")?;
    let sig = keypair
        .try_sign(&content)
        .with_context(|| "Failed to sign certificate content")?;

    let cert = Certificate {
        tbs_certificate: tbs,
        signature_algorithm: AlgorithmIdentifier {
            oid: ed25519_oid,
            parameters: None,
        },
        signature: BitString::from_bytes(&sig.to_bytes())
            .with_context(|| "Failed to convert signature to bytes")?,
    };

    Ok((keypair, cert))
}

fn generate_root_mldsa(
    infos: &CertificateFields,
) -> Result<(SecretKey, oqs::sig::PublicKey, Certificate), anyhow::Error> {
    // Create the root CA ML-DSA87 key pair
    let pq_scheme = match Sig::new(Algorithm::MlDsa87) {
        Ok(pq_s) => pq_s,
        Err(e) => return Err(anyhow!("Cannot construct new ML-DSA87 algorithm: {e}")),
    };
    let (pk, sk) = match pq_scheme.keypair() {
        Ok((public, secret)) => (public, secret),
        Err(e) => return Err(anyhow!("Cannot generate new ML-DSA87 keypair: {e}")),
    };

    // OID value for ml-dsa-sha512 from IBM's networking OID range
    let mldsa_oid = ObjectIdentifier::new(ML_DSA87_OID)?;

    // Root ML-DSA87 certificate will have this serial number
    let serial: [u8; 20] = [2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1];

    // Build subject DN
    let subject = infos.generate_dn()?;

    let tbs = infos.construct_tbs_certificate(
        &subject,
        &pk.clone().into_vec(),
        &serial,
        &mldsa_oid,
        true,
    )?;

    let content = tbs.to_der()?;

    let signature = match pq_scheme.sign(&content, &sk) {
        Ok(sig) => sig,
        Err(e) => return Err(anyhow!("Cannot sign message: {e}")),
    };

    let cert = Certificate {
        tbs_certificate: tbs,
        signature_algorithm: AlgorithmIdentifier {
            oid: mldsa_oid,
            parameters: None,
        },
        signature: BitString::from_bytes(&signature.into_vec())?,
    };

    Ok((sk, pk, cert))
}

impl HybridKeyPair {
    /// Save the keypair to disk
    /// The keys will be saved in DER encoded PKCS8 files at: keys_path/name-{cl|pq}.p8
    /// The certificates will be saved in PEM files at: certs_path/name-{cl|pq}.pem
    /// pwd is used for encrypting the PKCS8 files
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// * It fails to save either the classic or post-quantum private key. This could be due to issues with file creation, writing permissions, or the key encryption process.
    /// * It fails to encode the certificates to the PEM format.
    /// * It fails to create or write the certificate files to the specified path.
    pub fn save(
        &self,
        name: &str,
        keys_path: &Path,
        certs_path: &Path,
        pwd: &str,
    ) -> Result<(), anyhow::Error> {
        // Save keys
        let cl_key_path = keys_path.join(name.to_owned() + "-cl.p8");
        log::debug!("cl_key_path: {cl_key_path:?}");
        self.classic.save_keys(&cl_key_path, pwd)?;

        let pq_key_path = keys_path.join(name.to_owned() + "-pq.p8");
        log::debug!("pq_key_path: {pq_key_path:?}");
        self.pq.save_keys(&pq_key_path, pwd)?;

        // Save certificates
        let cl_cert_path = certs_path.join(name.to_owned() + "-cl.pem");
        let cl_pem = self.classic_cert.to_pem(LineEnding::LF)?;
        log::debug!("cl_cert_path: {cl_cert_path:?}");
        let mut cl_cert_file = File::create(cl_cert_path)?;
        write!(cl_cert_file, "{cl_pem}")?;

        let pq_cert_path = certs_path.join(name.to_owned() + "-pq.pem");
        let pq_pem = self.pq_cert.to_pem(LineEnding::LF)?;
        log::debug!("pq_cert_path: {pq_cert_path:?}");
        let mut pq_cert_file = File::create(pq_cert_path)?;
        write!(pq_cert_file, "{pq_pem}")?;

        Ok(())
    }

    /// Load the keypair from the disk
    /// The keys will be loaded in DER encoded PKCS8 files from: pki_dir/keys_path/name-{cl|pq}.p8
    /// The certificates will be loaded in PEM files from: pki_dir/certs_path/name-{cl|pq}.pem
    /// pwd is used for decrypting the PKCS8 files
    pub fn load(
        name: &str,
        keys_path: &Path,
        certs_path: &Path,
        pki_dir: &Path,
        pwd: &str,
    ) -> Result<HybridKeyPair, anyhow::Error> {
        // Load keys
        log::debug!("PKI dir: {pki_dir:?}");

        let keys_dir = pki_dir.join(".".to_owned() + &keys_path.to_string_lossy());
        log::debug!("Keys dir: {keys_dir:?}");

        let cl_key_path = keys_dir.join(name.to_owned() + "-cl.p8");
        log::debug!("Classic: {cl_key_path:?}");

        let classic: SigningKey = SigningKey::load_keys(&cl_key_path, pwd)?;
        let pq_key_path = keys_dir.join(name.to_owned() + "-pq.p8");
        log::debug!("PQ: {pq_key_path:?}");

        let pq = KeysasPQKey::load_keys(&pq_key_path, pwd)?;

        // Load certificates
        let certs_dir = pki_dir.join(".".to_owned() + &certs_path.to_string_lossy());

        let cl_cert_path = certs_dir.join(name.to_owned() + "-cl.pem");
        log::debug!("cl_cert_path: {cl_cert_path:?}");

        let cl_cert_pem = fs::read_to_string(cl_cert_path)?;
        let classic_cert = Certificate::from_pem(cl_cert_pem)?;

        let pq_cert_path = certs_dir.join(name.to_owned() + "-pq.pem");
        log::debug!("pq_cert_path: {pq_cert_path:?}");

        let pq_cert_pem = fs::read_to_string(pq_cert_path)?;
        let pq_cert = Certificate::from_pem(pq_cert_pem)?;

        Ok(HybridKeyPair {
            classic,
            classic_cert,
            pq,
            pq_cert,
        })
    }
    /// Generate PKI root keys
    pub fn generate_root(infos: &CertificateFields) -> Result<HybridKeyPair, anyhow::Error> {
        // Generate root ED25519 key and certificate
        let (kp_ed, cert_ed) =
            generate_root_ed25519(infos).with_context(|| "ED25519 generation failed")?;

        // Generate root ML-DSA87 key and certificate
        let (sk_dl, pk_dl, cert_dl) =
            generate_root_mldsa(infos).context("ML-DSA87 generation failed")?;

        Ok(HybridKeyPair {
            classic: kp_ed,
            classic_cert: cert_ed,
            pq: KeysasPQKey {
                private_key: sk_dl,
                public_key: pk_dl,
            },
            pq_cert: cert_dl,
        })
    }

    /// Generate a signed hybrid keypair (ED25519 and ML-DSA87)
    pub fn generate_signed_keypair(
        ca_keys: &HybridKeyPair,
        subject_name: &RdnSequence,
        pki_infos: &CertificateFields,
        is_app_key: bool,
    ) -> Result<HybridKeyPair, anyhow::Error> {
        // Generate ED25519 key and certificate
        // Create the ED25519 keypair
        let kp_ed: SigningKey = SigningKey::generate_new()?;
        // Construct a CSR for the ED25519 key
        let csr_ed = kp_ed.generate_csr(subject_name)?;
        // Generate a certificate from the CSR
        let cert_ed = generate_cert_from_csr(ca_keys, &csr_ed, pki_infos, is_app_key)?;

        // Generate ML-DSA87 key and certificate
        // Create the ML-DSA87 key pair
        let pq_scheme = match Sig::new(Algorithm::MlDsa87) {
            Ok(pq_s) => pq_s,
            Err(e) => return Err(anyhow!("Cannot construct new ML-DSA87 algorithm: {e}")),
        };
        let (pk_dl, sk_dl) = match pq_scheme.keypair() {
            Ok((public, secret)) => (public, secret),
            Err(e) => return Err(anyhow!("Cannot generate new ML-DSA87 keypair: {e}")),
        };
        let kp_pq = KeysasPQKey {
            private_key: sk_dl,
            public_key: pk_dl,
        };
        // Construct a CSR for the ML-DSA87 key
        let csr_dl = kp_pq.generate_csr(subject_name)?;
        // Generate a certificate from the CSR
        let cert_dl = generate_cert_from_csr(ca_keys, &csr_dl, pki_infos, is_app_key)?;

        // Construct hybrid key pair
        Ok(HybridKeyPair {
            classic: kp_ed,
            classic_cert: cert_ed,
            pq: kp_pq,
            pq_cert: cert_dl,
        })
    }
}

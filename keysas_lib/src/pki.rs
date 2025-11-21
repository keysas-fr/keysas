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

use anyhow::anyhow;
use oqs::sig::Algorithm;
use oqs::sig::Sig;
use rand_dl::RngCore;
use rand_dl::rngs::OsRng;
use x509_cert::certificate::*;
use x509_cert::der::Encode;
use x509_cert::request::CertReq;
use x509_cert::spki::ObjectIdentifier;

use crate::certificate_field::CertificateFields;
use crate::keysas_hybrid_keypair::HybridKeyPair;
use crate::keysas_key::KeysasKey;

// Profil des certificats
//
// Root CA profil
//  - Version: "2"
//  - Serial Number: "1"
//  - Signature
//  - Issuer => contains: countryName, organizationName, organizationalUnitName
//  - Validity
//  - Subject
//  - Subject Public key info
//  - [Unique Identifiers: Not used]
//  - Extensions
//      - Authority Key identifiers => Not critical, equals "Subject Key Identifiers"
//      - Subject Key identifiers   =>
//      - Basic constraints         => Critical, cA=True and pathLenConstraint=0
//      - Key usage                 => Critical, keyCertSign
//      - Certificate policies      => Not critical
//
// Station CA profil
//  - Version: "2"
//  - Serial Number: random
//  - Signature
//  - Issuer => contains: countryName, organizationName, organizationalUnitName
//  - Validity
//  - Subject
//  - Subject Public key info
//  - [Unique Identifiers: Not used]
//  - Extensions
//      - Authority Key identifiers => Not critical, equals "Subject Key Identifiers"
//      - Subject Key identifiers   =>
//      - Basic constraints         => Critical, cA=False and pathLenConstraint=1
//      - Key usage                 => Critical, keyCertSign
//      - Certificate policies      => Not critical
//
// Station file signing profil
//  - Version: "2"
//  - Serial Number: random
//  - Signature
//  - Issuer => contains: countryName, organizationName, organizationalUnitName
//  - Validity
//  - Subject
//  - Subject Public key info
//  - [Unique Identifiers: Not used]
//  - Extensions
//      - Authority Key identifiers => Not critical, equals "Subject Key Identifiers"
//      - Subject Key identifiers   =>
//      - Basic constraints         => Critical, cA=False and pathLenConstraint=1
//      - Key usage                 => Critical, digitalSignature
//      - Certificate policies      => Not critical
//
// USB signing profil
//  - Version: "2"
//  - Serial Number: random
//  - Signature
//  - Issuer => contains: countryName, organizationName, organizationalUnitName
//  - Validity
//  - Subject
//  - Subject Public key info
//  - [Unique Identifiers: Not used]
//  - Extensions
//      - Authority Key identifiers => Not critical, equals "Subject Key Identifiers"
//      - Subject Key identifiers   =>
//      - Basic constraints         => Critical, cA=False and pathLenConstraint=1
//      - Key usage                 => Critical, digitalSignature
//      - Certificate policies      => Not critical

pub const ML_DSA87_OID: &str = "2.16.840.1.101.3.4.3.19";
pub const ED25519_OID: &str = "1.3.101.112";

/// Generate a X509 certificate from a CSR and a CA keypair
/// is_app_cert is set to true if it is an application certificate, otherwise it
/// is considered to be a CA certificate
/// The certificate generated will always be for DigitalSignature
pub fn generate_cert_from_csr(
    ca_keys: &HybridKeyPair,
    csr: &CertReq,
    pki_info: &CertificateFields,
    is_app_cert: bool,
) -> Result<Certificate, anyhow::Error> {
    // Extract and validate info in the CSR
    let subject = csr.info.subject.clone();

    let pub_key = csr
        .info
        .public_key
        .subject_public_key
        .as_bytes()
        .ok_or(anyhow!("Subject public key missing"))?;

    let mldsa_oid = ObjectIdentifier::new(ML_DSA87_OID)?;
    let ed25519_oid = ObjectIdentifier::new(ED25519_OID)?;

    // Build the certificate
    if csr
        .info
        .public_key
        .algorithm
        .assert_algorithm_oid(ed25519_oid)
        .is_ok()
    {
        // Validate CSR authenticity
        let mut pub_key_casted: [u8; 32] = [0u8; 32];
        if pub_key.len() == 32 {
            pub_key_casted.copy_from_slice(pub_key);
        } else {
            return Err(anyhow!("Invalid public key length"));
        }

        let key = ed25519_dalek::VerifyingKey::from_bytes(&pub_key_casted)?;
        //let mut prehashed = Sha512::new();
        //prehashed.update(&csr.info.to_der()?);
        let mut csr_signature_casted: [u8; 64] = [0u8; 64];
        if csr.signature.raw_bytes().len() == 64 {
            csr_signature_casted.copy_from_slice(csr.signature.raw_bytes());
        } else {
            return Err(anyhow!("Invalid CSR signature: not 64 bytes long"));
        }
        if key
            .verify_strict(
                &csr.info.to_der()?,
                &ed25519_dalek::Signature::from_bytes(&csr_signature_casted),
            )
            .is_err()
        {
            return Err(anyhow!("Invalid CSR signature"));
        }

        // Generate serial number
        let mut serial = [0u8; 20];
        OsRng.fill_bytes(&mut serial);

        // Build the certificate
        let cert = ca_keys.classic.generate_certificate(
            pki_info,
            &subject,
            pub_key,
            &serial,
            is_app_cert,
        )?;

        Ok(cert)
    } else if csr
        .info
        .public_key
        .algorithm
        .assert_algorithm_oid(mldsa_oid)
        .is_ok()
    {
        // Validate CSR authenticity
        oqs::init();
        let pq_scheme = match Sig::new(Algorithm::MlDsa87) {
            Ok(pq_s) => pq_s,
            Err(e) => return Err(anyhow!("Cannot construct new ML-DSA87 algorithm: {e}")),
        };
        if pq_scheme
            .verify(
                &csr.info.to_der()?,
                pq_scheme
                    .signature_from_bytes(csr.signature.raw_bytes())
                    .ok_or(anyhow!("Failed to create signature"))?,
                pq_scheme
                    .public_key_from_bytes(pub_key)
                    .ok_or(anyhow!("Failed to create public key"))?,
            )
            .is_err()
        {
            return Err(anyhow!("Invalid CSR signature"));
        }

        // Generate serial number
        let mut serial = [0u8; 20];
        OsRng.fill_bytes(&mut serial);

        // Build the certificate
        let cert =
            ca_keys
                .pq
                .generate_certificate(pki_info, &subject, pub_key, &serial, is_app_cert)?;

        Ok(cert)
    } else {
        Err(anyhow!("Invalid algorithm OID"))
    }
}

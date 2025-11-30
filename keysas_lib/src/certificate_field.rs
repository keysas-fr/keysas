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

use anyhow::{Context, anyhow};
use der::Any;
use der::Tag;
use der::asn1::SetOfVec;
use der::oid::db::rfc4519;
use oqs::sig::{Algorithm, Sig};
use pkcs8::der::DecodePem;
use pkcs8::der::Encode;
use pkcs8::der::asn1::OctetString;
use pkcs8::der::oid::db::rfc5280;
use serde_derive::Serialize;
use std::time::Duration;
use x509_cert::attr::AttributeTypeAndValue;
use x509_cert::certificate::{Certificate, TbsCertificate, Version};
use x509_cert::der::asn1::BitString;
use x509_cert::ext::Extension;
use x509_cert::name::RdnSequence;
use x509_cert::name::RelativeDistinguishedName;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::AlgorithmIdentifier;
use x509_cert::spki::ObjectIdentifier;
use x509_cert::spki::SubjectPublicKeyInfo;
use x509_cert::time::Validity;

use crate::pki::ED25519_OID;
use crate::pki::ML_DSA87_OID;

/// Structure containing informations to build the certificate
#[derive(Debug, Clone, Serialize)]
pub struct CertificateFields {
    pub org_name: Option<String>,
    pub org_unit: Option<String>,
    pub country: Option<String>,
    pub common_name: Option<String>,
    pub validity: Option<u32>,
}

/// Validate a Certificate received in PEM format
/// Check that
///     - it can be parsed into a X509 certificate
///     - it is used for signing
///     - if there is a `ca_cert` supplied, it signed by the CA
///
/// # Arguments
///
/// * `pem` - Certificate in PEM format
/// * `ca_cert` - CA certificate either ED25519 or ML-DSA87
///
/// # Errors
///
/// This function will return an error in the following situations:
///
/// * The provided `pem` string cannot be parsed as a valid PEM certificate.
/// * The CA certificate's public key is not a valid ED25519 or ML-DSA87 key.
/// * The certificate's signature is invalid or the signature field is empty.
/// * The signature algorithm is not supported (not ED25519 or ML-DSA87).
/// * An error occurs during OQS initialization or algorithm construction for ML-DSA87.
/// * An error occurs when serializing the certificate to DER format for verification.
pub fn validate_signing_certificate(
    pem: &str,
    ca_cert: Option<&Certificate>,
) -> Result<Certificate, anyhow::Error> {
    // Parse the certificate
    let cert = Certificate::from_pem(pem)?;
    if let Some(ca) = ca_cert {
        match ca
            .tbs_certificate
            .subject_public_key_info
            .algorithm
            .oid
            .to_string()
            .as_str()
        {
            ED25519_OID => {
                log::debug!("Found Ed25519 OID");
                let ca_key_bytes =// Extract the CA public key
                    ca.tbs_certificate
                        .subject_public_key_info
                        .subject_public_key
                        .raw_bytes();
                // Prepare for the copy
                let mut ca_key_bytes_casted: [u8; 32] = [0; 32];
                if ca_key_bytes.len() == 32 {
                    ca_key_bytes_casted.copy_from_slice(ca_key_bytes);
                } else {
                    return Err(anyhow!(
                        "Cannot copy slice into ca_key_bytes_casted, not 32 bytes long"
                    ));
                }
                let ca_key = ed25519_dalek::VerifyingKey::from_bytes(&ca_key_bytes_casted)?;

                // Verify the certificate signature
                let cert_signature_bytes = cert
                    .signature
                    .as_bytes()
                    .ok_or_else(|| anyhow!("Signature field is empty"))?;
                let mut cert_signature_casted: [u8; 64] = [0; 64];
                if cert_signature_bytes.len() == 64 {
                    cert_signature_casted.copy_from_slice(cert_signature_bytes);
                } else {
                    return Err(anyhow!(
                        "Cannot copy slice into cert_signature_casted, not 64 bytes long"
                    ));
                }

                let sig = ed25519_dalek::Signature::from_bytes(&cert_signature_casted);
                ca_key.verify_strict(&cert.tbs_certificate.to_der()?, &sig)?;
                // If the signature is invalid an error is thrown
            }
            ML_DSA87_OID => {
                // Initialize liboqs
                log::info!("Found ML-DSA87 OID");
                oqs::init();

                // Extract the CA public key
                let pq_scheme = match Sig::new(Algorithm::MlDsa87) {
                    Ok(pq_s) => pq_s,
                    Err(e) => return Err(anyhow!("Cannot construct new ML-DSA87 algorithm: {e}")),
                };
                let ca_key = pq_scheme
                    .public_key_from_bytes(
                        ca.tbs_certificate
                            .subject_public_key_info
                            .subject_public_key
                            .raw_bytes(),
                    )
                    .ok_or_else(|| anyhow!("Invalid ML-DSA87 key"))?;

                // Verify the certificate signature
                let sig = pq_scheme
                    .signature_from_bytes(
                        cert.signature
                            .as_bytes()
                            .ok_or_else(|| anyhow!("Signature field is empty"))?,
                    )
                    .ok_or_else(|| anyhow!("Failed to parse pq signature field"))?;
                match pq_scheme.verify(&cert.tbs_certificate.to_der()?, sig, ca_key) {
                    Ok(_) => log::info!("Certificate is verified"),
                    Err(e) => return Err(anyhow!("Certificate is not verified: {e:?}")),
                }
                // If the signature is invalid an error is thrown
            }
            _ => {
                log::error!("OID not found for {ca_cert:?} !");
                return Err(anyhow!("Signature algorithm not supported"));
            }
        }
    } else {
        log::debug!("No ca_cert argument");
    }

    Ok(cert)
}

impl CertificateFields {
    /// Validate user input and construct a certificate fields structure that can be used
    /// to build the certificates of the PKI.
    /// The checks done are :
    ///     - Test if country is 2 letters long, if less return error, if more shorten it to the first two letters
    ///     - Test if validity can be converted to u32, if not generate error
    ///
    /// # Errors
    ///
    /// This function will return an error if the country name is less than two characters long,
    /// if the validity string cannot be parsed as a u32, or if the validity value is too
    /// large and would cause an overflow.
    pub fn from_fields<'a>(
        org_name: Option<&'a str>,
        org_unit: Option<&'a str>,
        country: Option<&'a str>,
        common_name: Option<&'a str>,
        validity: Option<&'a str>,
    ) -> Result<CertificateFields, anyhow::Error> {
        // Test if country is 2 letters long
        let cn = country
            .map(|name| match name.len() {
                0 | 1 => Err(anyhow!("Invalid country name")),
                2 => Ok(name.to_string()),
                _ => Ok(name[..2].to_string()),
            })
            .transpose()?;

        // Test if validity can be converted to u32
        let val = validity.map(|value| value.parse::<u32>()).transpose()?;
        if let Some(v) = val
            && v.checked_mul(86_400).is_none()
        {
            return Err(anyhow!("Validity value is too large"));
        }

        Ok(CertificateFields {
            org_name: org_name.map(|name| name.to_string()),
            org_unit: org_unit.map(|name| name.to_string()),
            country: cn,
            common_name: common_name.map(|name| name.to_string()),
            validity: val,
        })
    }

    /// Generate a distinghuished name from the input fields for the certificate
    ///
    /// # Errors
    ///
    /// This function will return an error if any of the certificate fields contain characters that are not valid for a `PrintableString`.
    pub fn generate_dn(&self) -> Result<RdnSequence, anyhow::Error> {
        let mut rdn: SetOfVec<AttributeTypeAndValue> = SetOfVec::new();

        // Add country name
        if let Some(cn) = &self.country {
            rdn.insert(AttributeTypeAndValue {
                oid: rfc4519::C,
                value: Any::new(Tag::PrintableString, cn.as_bytes())?,
            })?;
        }

        // Add organisation name
        if let Some(oa) = &self.org_name {
            rdn.insert(AttributeTypeAndValue {
                oid: rfc4519::O,
                value: Any::new(Tag::PrintableString, oa.as_bytes())?,
            })?;
        }

        // Add organisational unit
        if let Some(ou) = &self.org_unit {
            rdn.insert(AttributeTypeAndValue {
                oid: rfc4519::OU,
                value: Any::new(Tag::PrintableString, ou.as_bytes())?,
            })?;
        }

        // Add common name
        if let Some(co) = &self.common_name {
            rdn.insert(AttributeTypeAndValue {
                oid: rfc4519::CN,
                value: Any::new(Tag::PrintableString, co.as_bytes())?,
            })?;
        }

        let name = vec![RelativeDistinguishedName::from(rdn)];

        let rdn = RdnSequence::from(name);
        Ok(rdn)
    }

    /// Construct a information field for a certificate using the issuer `CertificateInfos`
    /// and the subject name and key
    /// The serial number is supplied by the caller that must ensure its uniqueness
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// * The `validity` field is not set.
    /// * The issuer's distinguished name cannot be generated.
    /// * The public key value cannot be converted to a `BitString`.
    /// * Any of the certificate extensions cannot be created or encoded.
    /// * The serial number cannot be generated.
    /// * The validity period for the certificate cannot be generated.
    pub fn construct_tbs_certificate(
        &self,
        subject_name: &RdnSequence,
        pub_value: &[u8],
        serial: &[u8; 20],
        algo_oid: &ObjectIdentifier,
        is_app_cert: bool,
    ) -> Result<TbsCertificate, anyhow::Error> {
        // Convert input validity from days to seconds
        let dur = match self.validity {
            Some(value) => Duration::new((value * 60 * 60 * 24).into(), 0),
            None => {
                return Err(anyhow!("Invalid validity value"));
            }
        };

        // Create Distinguished Names for issuer and subject
        let issuer_name = self.generate_dn()?;

        // Convert the public key value to a bit string
        let pub_key =
            BitString::from_bytes(pub_value).with_context(|| "Failed get public key raw value")?;

        // Generate the public key information field
        let pub_key_info = SubjectPublicKeyInfo {
            algorithm: AlgorithmIdentifier {
                oid: *algo_oid,
                parameters: None,
            },
            subject_public_key: pub_key,
        };

        // Create certificate extensions
        let mut extensions: Vec<Extension> = Vec::new();

        // Authority Key Identifier
        // According to RGS, this extension must be present and set to non critical
        // for application certificate
        if is_app_cert {
            extensions.push(Extension {
                extn_id: rfc5280::ID_CE_AUTHORITY_KEY_IDENTIFIER,
                critical: false,
                extn_value: OctetString::new(issuer_name.to_der()?)?,
            });
        }

        // Key usage
        // According to RGS, must be set to critical
        // Bit 0 is set to indicate digitalSignature
        let ku_value: [u8; 2] = [1, 0];
        extensions.push(Extension {
            extn_id: rfc5280::ID_CE_KEY_USAGE,
            critical: true,
            extn_value: OctetString::new(ku_value.to_vec())?,
        });

        // Generate the TBS Certificate structure
        // According to RGS:
        //  - Version is set to V3
        //  - Issuer and subject are set with distinguished names
        //  - Unique Identifiers are not used
        //  - Extensions are set
        log::debug!("Serial number generated is {serial:?}");
        let serial_number = SerialNumber::new(&serial[0..19])
            .with_context(|| "Failed to generate serial number")?;
        let tbs = TbsCertificate {
            version: Version::V3,
            serial_number,
            signature: AlgorithmIdentifier {
                oid: *algo_oid,
                parameters: None,
            },
            issuer: issuer_name,
            validity: Validity::from_now(dur)
                .with_context(|| "Failed to generate validity date")?,
            subject: subject_name.clone(),
            subject_public_key_info: pub_key_info,
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: Some(extensions),
        };
        Ok(tbs)
    }
}

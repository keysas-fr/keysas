// SPDX-License-Identifier: GPL-3.0-only
/*
 *
 * (C) Copyright 2019-2025 Stephane Neveu, Luc Bonnafoux
 *
 * This file contains various funtions for building and validating file report
 */

//! The report is JSON file containing the following structure:
//! ```json
//! {
//!     "metadata": {
//!         "name",             // String: File name
//!         "date",             // String DD-MM-YYYY_HH-mm-SS-NN: Date of creation of the report
//!         "file_type",        // String: file type
//!         "is_valid",         // Boolean: true if all checks passed
//!         "report": {
//!             "yara",         // String: yara detailed report
//!             "av",           // String: clamav detailed report
//!             "type_allowed", // Boolean: false if forbidden type detected
//!             "size",         // u64: file size
//!             "corrupted",    // boolean: true if file integrity corruption detected
//!             "toobig"        // Boolean, true file size is too big
//!         }
//!     },
//!     "binding" : {
//!         "file_digest",         // String: base64 encoded SHA256 digest of the file
//!         "metadata_digest",     // String: base64 encoded SHA256 digest of the metadata
//!         "station_certificate", // String: concatenation of the station signing certificates PEM
//!         "report_signature",    // String: base64 encoded concatenation of the ED25519 and ML-DSA87 signatures
//!     }
//! }
//! ```
//!
//! The report is signed by the station and validated by the usb firewall
//!

use crate::keysas_key::KeysasKey;
use crate::sha256_digest;
use crate::{
    certificate_field::validate_signing_certificate, keysas_hybrid_keypair::HybridKeyPair,
};
use anyhow::anyhow;
use base64::{Engine as _, engine::general_purpose};
use oqs::sig::{Algorithm, Sig};
use serde_derive::{Deserialize, Serialize};
use sha2::Sha256;
use std::fs::File;
use std::path::Path;
use time::OffsetDateTime;
use x509_cert::Certificate;

/// Metadata object in the report.
/// The structure can be serialized to JSON.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MetaData {
    /// Name of the file
    pub name: String,
    /// Date of the report creation
    pub date: String,
    /// Type of the file
    pub file_type: String,
    /// True if the file is correct
    pub is_valid: bool,
    /// Object containing the detailled [FileReport]
    pub report: FileReport,
}

/// Signature binding the file and the report.
/// the structure can be serialized to JSON.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Bd {
    /// SHA256 digest of the file encoded in base64
    pub file_digest: String,
    /// SHA256 digest of the [MetaData] associated to the file
    pub metadata_digest: String,
    /// Station certificates: concatenation of its ED25519 and ML-DSA87 signing certificates with a '|' delimiter
    pub station_certificate: String,
    /// Report signature: concatenation of the ED25519 and ML-DSA87 signatures in base64
    pub report_signature: String,
}

/// Report that will be created for each file.
/// The structure can be serialized to JSON.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Report {
    /// [MetaData] of the file analysis
    pub metadata: MetaData,
    /// [Bd] binding of the file and the report with the station signature
    pub binding: Bd,
}

/// Detailed report of the file checks.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FileReport {
    /// Detailed report of the yara checks
    pub yara: String,
    /// Detailed report of the clamav checks
    pub av: Vec<String>,
    /// True if the file type is allowed
    pub type_allowed: bool,
    /// Size of the file
    pub size: u64,
    /// True if a file corruption occured during the file processing
    pub corrupted: bool,
    /// True if the file size is too big
    pub toobig: bool,
}

/// Structure that holds a file metadata
#[derive(Debug, Serialize, Deserialize, Clone, bincode::Decode)]
pub struct FileMetadata {
    /// Name of the file
    pub filename: String,
    /// SHA256 digest of the file
    pub digest: String,
    /// True if a file corruption as occured during processing
    pub is_digest_ok: bool,
    /// True if the file is toobig
    pub is_toobig: bool,
    /// Size of the file
    pub size: u64,
    /// True if the file type is valid
    pub is_type_allowed: bool,
    /// True if clamav tests pass
    pub av_pass: bool,
    /// Detailed report of clamav if the test failed
    pub av_report: Vec<String>,
    /// True if yara tests pass
    pub yara_pass: bool,
    /// Detailed report of yara if the test failed
    pub yara_report: String,
    /// Timestamp of the file entering the station
    pub timestamp: String,
    /// True if a file corruption occured during the processing
    pub is_corrupted: bool,
    /// Type of the file
    pub file_type: String,
}

/// Wrapper around the report metadata creation
///
/// # Arguments
///
/// * `f` - File metadata received from keysas transit
pub fn generate_report_metadata(f: &FileMetadata) -> MetaData {
    let timestamp = format!(
        "{}-{}-{}_{}-{}-{}-{}",
        OffsetDateTime::now_utc().day(),
        OffsetDateTime::now_utc().month(),
        OffsetDateTime::now_utc().year(),
        OffsetDateTime::now_utc().hour(),
        OffsetDateTime::now_utc().minute(),
        OffsetDateTime::now_utc().second(),
        OffsetDateTime::now_utc().nanosecond()
    );

    let new_file_report = FileReport {
        yara: f.yara_report.clone(),
        av: f.av_report.clone(),
        type_allowed: f.is_type_allowed,
        size: f.size,
        corrupted: f.is_corrupted,
        toobig: f.is_toobig,
    };

    MetaData {
        name: f.filename.clone(),
        date: timestamp,
        file_type: f.file_type.clone(),
        is_valid: f.av_pass
            && f.yara_pass
            && !f.is_toobig
            && !f.is_corrupted
            && f.is_digest_ok
            && f.is_type_allowed,
        report: new_file_report,
    }
}

/// Bind the report to the file by signing with ED25519 and ML-DSA87 the concatenation
/// of the file digest and the report metadata digest.
/// The two signatures are concatenated (ED25519 first).
/// All the fields of the binding are encoded in base64
///
/// # Arguments
///
/// * `f` - Metadata from the file analysis, it is used to get the file digest
/// * `report_meta` - Report metadata that will be included in the json file
/// * `sign_keys` - Hybrid key pair to sign the report
/// * `sign_cert` - Hybrid key pair certificate that will be included in the report
pub fn bind_and_sign(
    f: &FileMetadata,
    report_meta: &MetaData,
    sign_keys: Option<&HybridKeyPair>,
    sign_cert: &str,
) -> Result<Report, anyhow::Error> {
    // Compute digest of report metadata
    let json_string = serde_json::to_string(&report_meta)?;

    let mut meta_digest = String::new();

    {
        // Import Trait digest localy to avoid collisation with Trait defined in ed25519_dalek
        use sha2::Digest;
        let mut hasher = Sha256::new();
        hasher.update(json_string.as_bytes());
        let result = hasher.finalize();
        meta_digest.push_str(&format!("{result:x}"));
    }

    // Sign the report and the file
    let concat = format!("{}-{}", f.digest, meta_digest);

    let mut signature = Vec::new();

    if let Some(keys) = sign_keys {
        // Sign with ED25519
        signature.append(&mut keys.classic.message_sign(concat.as_bytes())?);
        // Sign with ML-DSA87
        signature.append(&mut keys.pq.message_sign(concat.as_bytes())?);
    }

    // Generate the final report
    Ok(Report {
        metadata: report_meta.clone(),
        binding: Bd {
            file_digest: general_purpose::STANDARD.encode(f.digest.clone()),
            metadata_digest: general_purpose::STANDARD.encode(meta_digest),
            station_certificate: sign_cert.to_string(),
            report_signature: general_purpose::STANDARD.encode(signature),
        },
    })
}

/// Parse a json file and try to extract a valid report from it
/// The function returns an error if the file is invalid or if the report contained is invalid
/// If there are CA certificate available, use them to validate the certificates in the report
///
/// # Arguments
///
/// * `report_path` - Path to the file containing the report
/// * `file_path`   - Path to the file linked to the report
/// * `ca_cert_cl`  - ED25519 certificate of the authority, used to validate the certificate in the report
/// * `ca_cert_pq`  - ML-DSA87 certificate of the authority
pub fn parse_report(
    report_path: &Path,
    file_path: Option<&Path>,
    ca_cert_cl: Option<&Certificate>,
    ca_cert_pq: Option<&Certificate>,
) -> Result<Report, anyhow::Error> {
    // Open the report
    let report_content = match std::fs::read_to_string(report_path) {
        Ok(ct) => ct,
        Err(_) => {
            return Err(anyhow!("Failed to read report content"));
        }
    };

    // Parse the json and coerce it into a Report structure
    let report: Report = serde_json::from_str(report_content.as_str())?;

    // If the report is linked to a file, test that there is a path to it supplied
    if !report.metadata.name.is_empty() && file_path.is_none() {
        return Err(anyhow!("No file supplied with the report"));
    }

    // Extracts the certificate within the report and validate them
    let mut certs = report.binding.station_certificate.split('|');
    if certs.clone().count() != 2 {
        return Err(anyhow!("Invalid number of certificates"));
    }
    let cert_cl = validate_signing_certificate(
        certs.next().ok_or(anyhow!("No ED25519 certificate"))?,
        ca_cert_cl,
    )?;
    let cert_pq = validate_signing_certificate(
        certs
            .remainder()
            .ok_or(anyhow!("No ML-DSA87 certificate"))?,
        ca_cert_pq,
    )?;

    // Reference Validation
    // and create the signature message from the digest of the metadata and the linked file if there is one
    let mut message = String::new();
    {
        // Import Trait digest localy to avoid collisation with Trait defined in ed25519_dalek
        use sha2::Digest;

        // Compute the digest of the file
        if let Some(f) = file_path {
            let file_digest = sha256_digest(&File::open(f)?)?;
            // Validate that it corresponds to the reference in the binding
            if general_purpose::STANDARD.encode(&file_digest) != report.binding.file_digest {
                return Err(anyhow!("File reference is invalid"));
            }
            message.push_str(&file_digest);
        }

        // Add delimiter between the two digests
        message.push('-');

        // Compute digest of the report metadata section
        let mut hasher = Sha256::new();
        hasher.update(serde_json::to_string(&report.metadata)?.as_bytes());
        let meta_digest: String = format!("{:x}", hasher.finalize());
        // Validate that it corresponds to the reference in the binding
        if general_purpose::STANDARD.encode(&meta_digest) != report.binding.metadata_digest {
            return Err(anyhow!("Metadata reference is invalid"));
        }
        message.push_str(&meta_digest);
    }

    // Signature validation
    let signature = general_purpose::STANDARD.decode(&report.binding.report_signature)?;

    if signature.len() <= ed25519_dalek::SIGNATURE_LENGTH {
        return Err(anyhow!("Signature is too short"));
    }
    // Validate the signature with ED25519
    let cert_cl_bytes = cert_cl
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();
    let mut cert_cl_bytes_casted: [u8; 32] = [0u8; 32];
    if cert_cl_bytes.len() == 32 {
        cert_cl_bytes_casted.copy_from_slice(cert_cl_bytes);
    } else {
        return Err(anyhow!("Cannot copy from slice cert_cl_bytes"));
    }
    let pub_cl = ed25519_dalek::VerifyingKey::from_bytes(&cert_cl_bytes_casted)?;
    // SAFETY: Should not panic as len is checked previously as > 64
    let sign_cl_bytes = &signature[0..ed25519_dalek::SIGNATURE_LENGTH];
    let mut sign_cl_bytes_casted: [u8; 64] = [0u8; 64];
    if sign_cl_bytes.len() == 64 {
        sign_cl_bytes_casted.copy_from_slice(sign_cl_bytes);
    } else {
        return Err(anyhow!("Cannot copy from slice cert_cl_bytes"));
    }

    let sig_cl = ed25519_dalek::Signature::from_bytes(&sign_cl_bytes_casted);
    pub_cl.verify_strict(message.as_bytes(), &sig_cl)?;
    // If the signature is invalid, an error is thrown

    // Validate the signature with ML-DSA87
    oqs::init();
    let pq_scheme = match Sig::new(Algorithm::MlDsa87) {
        Ok(pq_s) => pq_s,
        Err(e) => return Err(anyhow!("Cannot construct new ML-DSA87 algorithm: {e}")),
    };
    let pub_pq = pq_scheme
        .public_key_from_bytes(
            cert_pq
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .raw_bytes(),
        )
        .ok_or_else(|| anyhow!("Failed to extract ML-DSA87 public key"))?;

    // SAFETY: should not panic as len has been verified as > 64
    let sig_pq = pq_scheme
        .signature_from_bytes(&signature[ed25519_dalek::SIGNATURE_LENGTH..])
        .ok_or_else(|| anyhow!("Failed to parse signature field"))?;
    match pq_scheme.verify(message.as_bytes(), sig_pq, pub_pq) {
        Ok(_) => log::info!("ML-DSA87 scheme is now verified"),
        Err(e) => return Err(anyhow!("ML-DSA87 scheme is not verified: {e}")),
    }
    // If the signature is invalid an error is thrown
    Ok(report)
}

#[cfg(test)]
mod tests_out {
    use crate::{certificate_field::CertificateFields, keysas_hybrid_keypair::HybridKeyPair};
    use base64::{Engine, engine::general_purpose};
    use oqs::sig::{Algorithm, Sig};
    use pkcs8::der::{DecodePem, EncodePem};
    use x509_cert::Certificate;

    use crate::file_report::{FileMetadata, bind_and_sign, generate_report_metadata};

    #[test]
    fn test_metadata_valid_file() {
        // Generate dummy file data
        let file_data = FileMetadata {
            filename: "test.txt".to_string(),
            digest: "00112233445566778899AABBCCDDEEFF".to_string(),
            is_digest_ok: true,
            is_toobig: false,
            size: 42,
            is_type_allowed: true,
            av_pass: true,
            av_report: Vec::new(),
            yara_pass: true,
            yara_report: "".to_string(),
            timestamp: "timestamp".to_string(),
            is_corrupted: false,
            file_type: "txt".to_string(),
        };

        // Generate report metadata
        let meta = generate_report_metadata(&file_data);

        // Validate fields
        assert_eq!(file_data.filename, meta.name);
        assert_eq!(file_data.file_type, meta.file_type);
        assert_eq!(meta.is_valid, true);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_bind_and_sign() {
        // Generate temporary keys
        let infos =
            CertificateFields::from_fields(None, None, None, Some("Test_station"), Some("200"))
                .unwrap();
        let sign_keys = HybridKeyPair::generate_root(&infos).unwrap();

        let mut sign_cert = String::new();
        let pem_cl = sign_keys
            .classic_cert
            .to_pem(pkcs8::LineEnding::LF)
            .unwrap();
        sign_cert.push_str(&pem_cl);
        // Add a delimiter between the two certificates
        sign_cert.push('|');
        let pem_pq = sign_keys.pq_cert.to_pem(pkcs8::LineEnding::LF).unwrap();
        sign_cert.push_str(&pem_pq);

        // Generate dummy file data
        let file_data = FileMetadata {
            filename: "test.txt".to_string(),
            digest: "00112233445566778899AABBCCDDEEFF".to_string(),
            is_digest_ok: true,
            is_toobig: false,
            size: 42,
            is_type_allowed: true,
            av_pass: true,
            av_report: Vec::new(),
            yara_pass: true,
            yara_report: "".to_string(),
            timestamp: "timestamp".to_string(),
            is_corrupted: false,
            file_type: "txt".to_string(),
        };

        let meta = generate_report_metadata(&file_data);

        let report = bind_and_sign(&file_data, &meta, Some(&sign_keys), &sign_cert).unwrap();
        // Test the generated report
        // Reconstruct the public keys from the binding certficates
        let mut certs = report.binding.station_certificate.split('|');
        let cert_cl = Certificate::from_pem(certs.next().unwrap()).unwrap();
        let cert_pq = Certificate::from_pem(certs.remainder().unwrap()).unwrap();

        let mut pub_cl_casted: [u8; 32] = [0u8; 32];
        let pub_cl_bytes = cert_cl
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes();
        if pub_cl_bytes.len() == 32 {
            pub_cl_casted.copy_from_slice(pub_cl_bytes);
        } else {
            panic!("Public key is not 32 bytes long !");
        }
        let pub_cl = ed25519_dalek::VerifyingKey::from_bytes(&pub_cl_casted).unwrap();
        oqs::init();
        let pq_scheme = Sig::new(Algorithm::MlDsa87).unwrap();
        let pub_pq = pq_scheme
            .public_key_from_bytes(
                cert_pq
                    .tbs_certificate
                    .subject_public_key_info
                    .subject_public_key
                    .raw_bytes(),
            )
            .unwrap();

        // Verify the signature of the report
        let signature = general_purpose::STANDARD
            .decode(report.binding.report_signature)
            .unwrap();
        let concat = format!(
            "{}-{}",
            String::from_utf8(
                general_purpose::STANDARD
                    .decode(report.binding.file_digest)
                    .unwrap()
            )
            .unwrap(),
            String::from_utf8(
                general_purpose::STANDARD
                    .decode(report.binding.metadata_digest)
                    .unwrap()
            )
            .unwrap()
        );
        let mut sig_casted: [u8; 64] = [0u8; 64];
        if signature[0..ed25519_dalek::SIGNATURE_LENGTH].len() == 64 {
            sig_casted.copy_from_slice(&signature[0..ed25519_dalek::SIGNATURE_LENGTH]);
        } else {
            panic!("Signature is not 64 bytes long!");
        }
        assert_eq!(
            true,
            pub_cl
                .verify_strict(
                    concat.as_bytes(),
                    &ed25519_dalek::Signature::from_bytes(&sig_casted)
                )
                .is_ok()
        );

        assert_eq!(
            true,
            pq_scheme
                .verify(
                    concat.as_bytes(),
                    pq_scheme
                        .signature_from_bytes(&signature[ed25519_dalek::SIGNATURE_LENGTH..])
                        .unwrap(),
                    pub_pq
                )
                .is_ok()
        );
    }
}

use crate::ssh_wrapper::KeysasSshSession;
use crate::ssh_wrapper::session_exec;
use crate::store::{drop_pki, init_store, set_pki_config};
use anyhow::anyhow;
use keysas_lib::certificate_field::{CertificateFields, validate_signing_certificate};
use keysas_lib::keysas_hybrid_keypair::HybridKeyPair;
use pkcs8::LineEnding;
use pkcs8::der::EncodePem;
use shlex::try_quote;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use x509_cert::Certificate;
use x509_cert::der::DecodePem;
use x509_cert::request::CertReq;

// Key names won't change
const ST_CA_KEY_NAME: &str = "st-ca";
const USB_CA_KEY_NAME: &str = "usb";
const PKI_ROOT_KEY_NAME: &str = "root";

/// Wrapper function to triger a signing key generation on a station and
/// recover CSRs from it
pub async fn cmd_generate_key_and_get_csr(
    session: &mut KeysasSshSession,
    name: &str,
) -> Result<(CertReq, CertReq), anyhow::Error> {
    let name_escaped = try_quote(name)?;
    let command = format!(
        "{}{}{}",
        "sudo /usr/bin/keysas-sign --generate", " --name ", name_escaped
    );
    log::error!("Command: {command:?}");
    let cmd_res = match session_exec(session, &command).await {
        Ok(res) => res,
        Err(why) => {
            log::error!("Error on send_command: {why:?}");
            return Err(anyhow!("Connection failed"));
        }
    };

    let cert_req = String::from_utf8(cmd_res)?;
    log::debug!("{cert_req:?}");

    // Recover the CSR from the session command
    let mut csrs = cert_req.split('|');
    let csr_cl = match csrs.next().and_then(|pem| match CertReq::from_pem(pem) {
        Ok(c) => Some(c),
        Err(e) => {
            log::error!("Failed to parse classic certification request (1): {e}");
            None
        }
    }) {
        Some(csr) => csr,
        None => {
            return Err(anyhow!("Failed to parse classic certification request (2)"));
        }
    };

    let csr_pq = match csrs.remainder().and_then(|pem| {
        match CertReq::from_pem(pem.trim_end_matches("\n\n")) {
            Ok(c) => Some(c),
            Err(e) => {
                log::debug!("{pem:?}");
                log::error!("Failed to parse PQC certification request (1): {e}");
                None
            }
        }
    }) {
        Some(csr) => csr,
        None => {
            return Err(anyhow!("Failed to parse PQC certification request (2)"));
        }
    };

    Ok((csr_cl, csr_pq))
}

/// Utility function to load a certificate on the station
/// Kind:
///     - file-cl: certificate for ED25519 station files signing
///     - file-pq: certificate for ML-DSA87 station files signing
///     - usb-cl: certificate for ED25519 USB signing
///     - usb-pq: certificate for ML-DSA87 USB signing
pub async fn send_cert_to_station(
    session: &mut KeysasSshSession,
    cert: &Certificate,
    kind: &str,
) -> Result<(), anyhow::Error> {
    let output = String::from_utf8(cert.to_pem(LineEnding::LF)?.into())?;

    let command = format!(
        "{}{}{}{}",
        "sudo /usr/bin/keysas-sign --load --certtype ",
        kind,
        " --cert=",
        "\"".to_owned() + &output + "\"",
    );

    if let Err(e) = session_exec(session, &command).await {
        log::error!("Failed to load certificate on the station: {e}");
        return Err(anyhow!("Connection error"));
    }

    let command = "sudo /bin/chown keysas-out:keysas-out /etc/keysas/file-sign-cl.p8 /etc/keysas/file-sign-cl.pem /etc/keysas/file-sign-pq.p8 /etc/keysas/file-sign-pq.pem /etc/keysas/usb-ca-cl.pem /etc/keysas/usb-ca-pq.pem".to_string();

    if let Err(e) = session_exec(session, &command).await {
        log::error!("Failed to chown files: {e}");
        return Err(anyhow!("Connection error"));
    }

    let command = "sudo /bin/systemctl restart keysas".to_string();

    if let Err(e) = session_exec(session, &command).await {
        log::error!("Failed to restart Keysas: {e}");
        return Err(anyhow!("Connection error"));
    }

    Ok(())
}

pub fn save_certificate(cert: &Certificate, path: &Path) -> Result<(), anyhow::Error> {
    let output = String::from_utf8(cert.to_pem(LineEnding::LF)?.into())?;
    let mut file = File::create(path)?;
    write!(file, "{output}")?;
    Ok(())
}

/// Test if every directories and p8 and pem files are presents
/// into the right path.
/// Test station and USB certificat signatures by the root CA
/// Flush the database and store the new configuration.
pub async fn check_restore_pki(
    base_directory: &String,
    admin_pwd: &str,
) -> Result<(), anyhow::Error> {
    let base_directory = Path::new(base_directory);
    // Step 1: Any directories or files bellow must be found
    let directories_and_files = [
        ("root", "root-cl.p8"),
        ("root", "root-cl.pem"),
        ("root", "root-pq.p8"),
        ("root", "root-pq.pem"),
        ("st", "st-ca-cl.p8"),
        ("st", "st-ca-cl.pem"),
        ("st", "st-ca-pq.p8"),
        ("st", "st-ca-pq.pem"),
        ("usb", "usb-cl.p8"),
        ("usb", "usb-cl.pem"),
        ("usb", "usb-pq.p8"),
        ("usb", "usb-pq.pem"),
    ];
    if base_directory.join("CA").is_dir() {
        for (directory, file) in directories_and_files.iter() {
            let subdirectory_path = base_directory.join("CA").join(directory);
            let file_path = subdirectory_path.join(file);

            if subdirectory_path.exists() && subdirectory_path.is_dir() {
                if file_path.exists() && file_path.is_file() {
                    log::debug!("Found file {file} in directory {directory}.");
                } else {
                    log::error!("File {file} not found in directory {directory}.");
                    return Err(anyhow!("Invalid algorithm OID"));
                }
            } else {
                log::error!("Directory {subdirectory_path:?} doesn't exist.");
                return Err(anyhow!("Directory do not exist"));
            }
        }
    } else {
        return Err(anyhow!("Directory CA does not exist."));
    }
    // Now let's validate the certificates before importing them into db

    let root_keys = match HybridKeyPair::load(
        PKI_ROOT_KEY_NAME,
        Path::new("/CA/root"),
        Path::new("/CA/root"),
        Path::new(&(base_directory.to_owned())),
        admin_pwd,
    ) {
        Ok(root_k) => root_k,
        Err(why) => {
            log::error!("Failed to load station key from disk: {why}");
            return Err(anyhow!("PKI error: cannot open st HybridkeyPair"));
        }
    };

    validate_signing_certificate(
        &root_keys.classic_cert.to_pem(LineEnding::LF)?,
        Some(&root_keys.classic_cert),
    )
    .map_err(|why| anyhow!("Error validating root ed25519 certificate: {:?}", why))?;
    log::debug!("Root Ed25519 certificate validated.");

    validate_signing_certificate(
        &root_keys.pq_cert.to_pem(LineEnding::LF)?,
        Some(&root_keys.pq_cert),
    )
    .map_err(|why| anyhow!("Error validating root PQC certificate: {:?}", why))?;
    log::debug!("Root PQC certificate validated.");

    let st_keys = match HybridKeyPair::load(
        ST_CA_KEY_NAME,
        Path::new("/CA/st"),
        Path::new("/CA/st"),
        Path::new(&(base_directory.to_owned())),
        admin_pwd,
    ) {
        Ok(st_k) => st_k,
        Err(why) => {
            log::error!("Failed to load station key from disk: {why}");
            return Err(anyhow!("PKI error: cannot open station HybridkeyPair"));
        }
    };

    match validate_signing_certificate(
        &st_keys.classic_cert.to_pem(LineEnding::LF)?,
        Some(&root_keys.classic_cert),
    ) {
        Ok(_) => log::debug!("Ed25519 station certificate signature is valid."),
        Err(why) => {
            return Err(anyhow!(
                "Error validating station Ed25519 certificate signature: {:?}",
                why
            ));
        }
    }
    log::debug!("Station Ed25519 certificate validated.");

    match validate_signing_certificate(
        &st_keys.pq_cert.to_pem(LineEnding::LF)?,
        Some(&root_keys.pq_cert),
    ) {
        Ok(_) => log::debug!("ML-DSA87 station certificate signature is valid."),
        Err(why) => {
            return Err(anyhow!(
                "Error validating station ML-DSA87 certificate signature: {:?}",
                why
            ));
        }
    }
    log::debug!("Station ML-DSA87 certificate validated.");

    let usb_keys = match HybridKeyPair::load(
        USB_CA_KEY_NAME,
        Path::new("/CA/usb"),
        Path::new("/CA/usb"),
        Path::new(&(base_directory.to_owned())),
        admin_pwd,
    ) {
        Ok(usb_k) => usb_k,
        Err(why) => {
            log::error!("Failed to load usb key from disk: {why}");
            return Err(anyhow!("PKI error: cannot open station HybridkeyPair"));
        }
    };

    match validate_signing_certificate(
        &usb_keys.classic_cert.to_pem(LineEnding::LF)?,
        Some(&root_keys.classic_cert),
    ) {
        Ok(_) => log::debug!("Ed25519 USB certificate signature is valid."),
        Err(why) => {
            return Err(anyhow!(
                "Error validating USB Ed25519 certificate signature: {:?}",
                why
            ));
        }
    }
    log::debug!("Station Ed25519 certificate validated.");

    match validate_signing_certificate(
        &usb_keys.pq_cert.to_pem(LineEnding::LF)?,
        Some(&root_keys.pq_cert),
    ) {
        Ok(_) => log::debug!("ML-DSA87 USB certificate signature is valid."),
        Err(why) => {
            return Err(anyhow!(
                "Error validating USB ML-DSA87 certificate signature: {:?}",
                why
            ));
        }
    }
    log::debug!("USB ML-DSA87 certificate validated.");
    log::info!("PKI provided is valid.");
    log::info!("Writing loaded configuration to database...");
    drop_pki().await?;
    static STORE_PATH: &str = ".keysas.dat";
    init_store(STORE_PATH)?;
    let pki_dir = match base_directory.to_str() {
        Some(s) => String::from(s),
        None => {
            log::error!("Cannot convert pki_directory into string");
            return Err(anyhow!("Store error: cannot convert PKI directory"));
        }
    };
    let valid = root_keys
        .classic_cert
        .tbs_certificate
        .validity
        .not_after
        .to_unix_duration()
        - root_keys
            .classic_cert
            .tbs_certificate
            .validity
            .not_before
            .to_unix_duration();
    log::debug!("Found validity: {} ", valid.as_secs() / 86400);
    let name = &root_keys.classic_cert.tbs_certificate.subject.to_string();
    let attribute_strings: Vec<&str> = name.split('+').collect();

    let mut country = "";
    let mut organization = "";
    let mut organizational_unit = "";

    // Parcours des attributs
    for attribute_str in attribute_strings {
        let parts: Vec<&str> = attribute_str.splitn(2, '=').collect();
        if parts.len() == 2 {
            let attr_type = parts[0].trim();
            let attr_value = parts[1].trim();
            match attr_type {
                "C" => country = attr_value,
                "O" => organization = attr_value,
                "OU" => organizational_unit = attr_value,
                _ => {} // Gérez d'autres attributs si nécessaire
            }
        } else {
            log::error!("RdnSequence not valid: length is not 2");
            return Err(anyhow!("RdnSequence not valid: length is not 2"));
        }
    }
    log::debug!("Found Country: {country} ");
    log::debug!("Found organization: {organization} ");
    log::debug!("Found organizational_unit: {organizational_unit} ");
    if !country.is_empty() && !organization.is_empty() && !organizational_unit.is_empty() {
        let cert_infos = CertificateFields {
            org_name: Some(organization.to_string()),
            org_unit: Some(organizational_unit.to_string()),
            country: Some(country.to_string()),
            common_name: None,
            validity: Some((valid.as_secs() / 86400) as u32),
        };
        if let Err(e) = set_pki_config(&pki_dir, &cert_infos) {
            log::error!("Failed to save PKI configuration: {e}");
            return Err(anyhow!("Store error: cannot set new PKI configuration"));
        }
    } else {
        log::error!("RdnSequence tags not correctly parsed");
        return Err(anyhow!("RdnSequence tags not correctly parsed"));
    }

    Ok(())
}

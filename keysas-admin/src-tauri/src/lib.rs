// Add on
// SPDX-License-Identifier: GPL-3.0-only
/*
 * The "keysas-admin".
 *
 * (C) Copyright 2019-2025 Stephane Neveu
 *
 * This file contains the main function.
 */
#![feature(str_split_remainder)]

use anyhow::anyhow;
//use async_std::task;
use keysas_lib::certificate_field::CertificateFields;
use keysas_lib::keysas_hybrid_keypair::HybridKeyPair;
use keysas_lib::pki::generate_cert_from_csr;
use std::fs;
use std::path::Path;
use tauri::command;

mod ssh_wrapper;
use crate::ssh_wrapper::*;
mod store;
use crate::store::*;
mod utils;
use crate::utils::*;
mod usb_sign;
use crate::usb_sign::*;

static STORE_PATH: &str = ".keysas.dat";

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Initialize liboqs
    oqs::init();

    // Tauri init
    tauri::Builder::default()
        .plugin(
            tauri_plugin_log::Builder::new()
                .target(tauri_plugin_log::Target::new(
                    tauri_plugin_log::TargetKind::Stdout,
                ))
                .build(),
        )
        .plugin(tauri_plugin_store::Builder::new().build())
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
            }
            Ok(())
        })
        .setup(|_app| {
            if let Err(e) = init_store(STORE_PATH) {
                return Err(e.into());
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            reboot,
            update,
            init_keysas,
            shutdown,
            export_sshpubkey,
            is_alive,
            sign_key,
            validate_privatekey,
            validate_rootkey,
            generate_pki_in_dir,
            save_sshkeys,
            get_sshkeys,
            save_station,
            get_station_ip,
            list_stations,
            remove_station,
            get_pki_config,
            get_pki_path,
            revoke_usb,
            del_pki,
            restore_pki,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

// Key names won't change
const ST_CA_KEY_NAME: &str = "st-ca";
const USB_CA_KEY_NAME: &str = "usb";
const PKI_ROOT_KEY_NAME: &str = "root";

// Define PKI paths for GNU/Linux
#[cfg(target_os = "linux")]
const _CA_DIR: &str = "/CA";
#[cfg(target_os = "linux")]
const ST_CA_SUB_DIR: &str = "/./CA/st";
#[cfg(target_os = "linux")]
const USB_CA_SUB_DIR: &str = "/./CA/usb";
#[cfg(target_os = "linux")]
const PKI_ROOT_SUB_DIR: &str = "/CA/root";
#[cfg(target_os = "linux")]
const _CRL_DIR: &str = "/CRL";
#[cfg(target_os = "linux")]
const CERT_DIR: &str = "/CERT/";

// Define PKI paths for windows
// TODO: test it on windows !
#[cfg(target_os = "windows")]
const _CA_DIR: &str = "\\CA";
#[cfg(target_os = "windows")]
const ST_CA_SUB_DIR: &str = "\\.\\CA\\st";
#[cfg(target_os = "windows")]
const USB_CA_SUB_DIR: &str = "\\.\\CA\\usb";
#[cfg(target_os = "windows")]
const PKI_ROOT_SUB_DIR: &str = "\\CA\\root";
#[cfg(target_os = "windows")]
const _CRL_DIR: &str = "\\CRL";
#[cfg(target_os = "windows")]
const CERT_DIR: &str = "\\CERT\\";

fn create_dir_if_not_exist(path: &String) -> Result<(), anyhow::Error> {
    if !Path::new(path).is_dir() {
        fs::create_dir(path)?;
    }
    Ok(())
}

/// Create the PKI directory hierachy as follows
/// pki_dir
/// |-- CA
/// |   |--root
/// |   |--st
/// |   |--usb
/// |--CRL
/// |--CERT
#[cfg(target_os = "linux")]
fn create_pki_dir(pki_dir: &String) -> Result<(), anyhow::Error> {
    // Test if the directory path is valid
    log::info!("Creating pki directories");
    if !Path::new(&pki_dir.trim()).is_dir() {
        return Err(anyhow!("Invalid PKI directory path"));
    }

    create_dir_if_not_exist(&(pki_dir.to_owned() + "/CA"))?;
    create_dir_if_not_exist(&(pki_dir.to_owned() + "/CA/root"))?;
    create_dir_if_not_exist(&(pki_dir.to_owned() + "/CA/st"))?;
    create_dir_if_not_exist(&(pki_dir.to_owned() + "/CA/usb"))?;
    create_dir_if_not_exist(&(pki_dir.to_owned() + "/CRL"))?;
    create_dir_if_not_exist(&(pki_dir.to_owned() + "/CERT"))?;
    Ok(())
}

#[cfg(target_os = "windows")]
fn create_pki_dir(pki_dir: &String) -> Result<(), anyhow::Error> {
    // Test if the directory path is valid
    if !Path::new(&pki_dir.trim()).is_dir() {
        return Err(anyhow!("Invalid PKI directory path"));
    }

    create_dir_if_not_exist(&(pki_dir.to_owned() + "\\CA"))?;
    create_dir_if_not_exist(&(pki_dir.to_owned() + "\\CA\\root"))?;
    create_dir_if_not_exist(&(pki_dir.to_owned() + "\\CA\\st"))?;
    create_dir_if_not_exist(&(pki_dir.to_owned() + "\\CA\\usb"))?;
    create_dir_if_not_exist(&(pki_dir.to_owned() + "\\CRL"))?;
    create_dir_if_not_exist(&(pki_dir.to_owned() + "\\CERT"))?;
    Ok(())
}

/// This command saves the path to the public and private SSH keys
/// If a path already exists it is replaced
/// The returned value is a boolean indicating if an error occured during
/// the execution (true: result is ok, false: error)
#[command]
async fn save_sshkeys(public: String, private: String) -> bool {
    match set_ssh(&public, &private) {
        Ok(_) => true,
        Err(e) => {
            log::error!("Failed to save ssh keys: {e}");
            false
        }
    }
}

/// This functions get the path to the public and private SSH keys
/// The first returned value is a boolean indicating if an error occured during
/// the execution (true: result is ok, false: error)
#[command]
async fn get_sshkeys() -> Result<(String, String), String> {
    match get_ssh() {
        Ok((public, private)) => Ok((public, private)),
        Err(e) => {
            log::error!("Failed to get ssh keys: {e}");
            Err(String::from("Store error"))
        }
    }
}

/// This functions drop the ca_table from the DB to remove the PKI configuration
/// The first returned value is a boolean indicating if an error occured during
/// the execution (true: result is ok, false: error)
#[command]
async fn del_pki() -> Result<(), String> {
    match drop_pki().await {
        Ok(()) => Ok(()),
        Err(e) => {
            log::error!("Failed to get ssh keys: {e}");
            Err(String::from("Store error"))
        }
    }
}

/// This function saves a station configuration in the database
/// If a station already exists with the same name, it is replaced
/// The returned value contains a boolean indicating if an error occured during
/// the execution (true: result is ok, false: error)
#[command]
async fn save_station(name: String, ip: String) -> bool {
    log::info!("Saved station");
    match set_station(&name, &ip) {
        Ok(_) => {
            log::info!("Saved station");
            true
        }
        Err(e) => {
            log::error!("Failed to save station: {e}");
            false
        }
    }
}

/// This function delete a Keysas station from the database.
#[command]
async fn remove_station(name: String) -> bool {
    match delete_station(&name) {
        Ok(_) => true,
        Err(e) => {
            log::error!("Failed to delete station: {e}");
            false
        }
    }
}

/// This function returns the IP address of a station registered in the database
/// The returned value contains a boolean indicating if an error occured during
/// the execution (true: result is ok, false: error)
#[command]
async fn get_station_ip(name: String) -> Result<String, String> {
    match get_station_ip_by_name(&name) {
        Ok(res) => Ok(res),
        Err(e) => {
            log::error!("Failed to get station IP: {e}");
            Err(String::from("Store error"))
        }
    }
}

/// This functions returns a list of all the station name and IP address stored
/// The list is a JSON of the form "[{name, ip}]"
#[command]
async fn list_stations() -> Result<String, String> {
    match get_station_list() {
        Ok(res) => {
            let result = match serde_json::to_string(&res) {
                Ok(r) => r,
                Err(e) => {
                    log::error!("Failed to serialize result: {e}");
                    return Err(String::from("Invalid result"));
                }
            };
            log::debug!("Station list: {result}");
            Ok(result)
        }
        Err(e) => {
            log::error!("Failed to get station IP: {e}");
            Err(String::from("Store error"))
        }
    }
}

/// This function initialize the keys in the station by
///  1. Generate a key pair for file signature on the station
///  2. Recover the public part of the key
///  3. Generate a certificate for the public key
///  4. Export the created certificate on the station
///  5. Finally it loads the admin USB signing certificate on the station
#[command]
async fn init_keysas(ip: String, name: String, ca_pwd: String) -> Result<String, String> {
    /* Get admin configuration from the store */
    // Get SSH key
    let ssh_key = match get_ssh() {
        Ok((_, private)) => private,
        Err(e) => {
            log::error!("Failed to get private key: {e}");
            return Err(String::from("No SSH key"));
        }
    };

    // Get path to PKI directory
    let pki_dir = match get_pki_dir() {
        Ok(dir) => dir,
        Err(e) => {
            log::error!("Failed to get PKI directory: {e}");
            return Err(String::from("Invalid PKI configuration"));
        }
    };

    // Get PKI info
    let pki_info = match get_pki_info() {
        Ok(info) => info,
        Err(e) => {
            log::error!("Failed to get PKI informations: {e}");
            return Err(String::from("Invalid PKI configuration"));
        }
    };

    // Connect to the host
    let mut session = match connect_key(&ip, &ssh_key).await {
        Ok(tu) => tu,
        Err(e) => {
            log::error!("Failed to open ssh connection with station: {e}");
            return Err(String::from("Connection failed"));
        }
    };

    //  1. Generate a key pair for file signature on the station
    //  2. Recover the CSR for the keys
    let (csr_cl, csr_pq) = match cmd_generate_key_and_get_csr(&mut session, &name).await {
        Ok(csrs) => csrs,
        Err(e) => {
            log::error!("Failed to generate key on station and get CSR: {e}");
            session.close().await;
            return Err(String::from("PKI error"));
        }
    };

    // 3. Generate a certificate from the request
    // Load station CA keypair
    let st_ca_keys = match HybridKeyPair::load(
        ST_CA_KEY_NAME,
        Path::new(ST_CA_SUB_DIR),
        Path::new(ST_CA_SUB_DIR),
        Path::new(&pki_dir),
        &ca_pwd,
    ) {
        Ok(k) => k,
        Err(e) => {
            log::error!("Failed to load station CA key: {e}");
            session.close().await;
            return Err(String::from("PKI error"));
        }
    };

    // Load USB CA keypair
    let usb_keys = match HybridKeyPair::load(
        USB_CA_KEY_NAME,
        Path::new(USB_CA_SUB_DIR),
        Path::new(USB_CA_SUB_DIR),
        Path::new(&pki_dir),
        &ca_pwd,
    ) {
        Ok(k) => k,
        Err(e) => {
            log::error!("Failed to load station USB key: {e}");
            session.close().await;
            return Err(String::from("PKI error"));
        }
    };

    // Generate certificate
    let cert_cl = match generate_cert_from_csr(&st_ca_keys, &csr_cl, &pki_info, true) {
        Ok(c) => c,
        Err(e) => {
            log::error!("Failed to generate certificate from request: {e}");
            session.close().await;
            return Err(String::from("PKI error"));
        }
    };

    let cert_pq = match generate_cert_from_csr(&st_ca_keys, &csr_pq, &pki_info, true) {
        Ok(c) => c,
        Err(e) => {
            log::error!("Failed to generate certificate from request: {e}");
            session.close().await;
            return Err(String::from("PKI error"));
        }
    };

    // Save certificates
    let path_cl = pki_dir.clone() + CERT_DIR + &name + "-cl.pem";
    log::debug!("path_cl ST-PEM: {path_cl}");
    if let Err(e) = save_certificate(&cert_cl, Path::new(&path_cl)) {
        log::error!("Failed to save station certificate: {e}");
        session.close().await;
        return Err(String::from("PKI error"));
    }

    let path_pq = pki_dir + CERT_DIR + &name + "-pq.pem";
    log::debug!("path_pq ST-PEM: {path_pq}");

    if let Err(e) = save_certificate(&cert_cl, Path::new(&path_pq)) {
        log::error!("Failed to save station certificate: {e}");
        session.close().await;
        return Err(String::from("PKI error"));
    }

    // 4. Export the created certificates on the station
    if let Err(e) = send_cert_to_station(&mut session, &cert_cl, "file-cl").await {
        log::error!("Failed to load certificate on the station: {e}");
        session.close().await;
        return Err(String::from("Connection error"));
    }

    if let Err(e) = send_cert_to_station(&mut session, &cert_pq, "file-pq").await {
        log::error!("Failed to load certificate on the station: {e}");
        session.close().await;
        return Err(String::from("Connection error"));
    }

    // 5. Finally it loads the admin USB signing certificate
    if let Err(e) = send_cert_to_station(&mut session, &usb_keys.classic_cert, "usb-cl").await {
        log::error!("Failed to load certificate on the station: {e}");
        session.close().await;
        return Err(String::from("Connection error"));
    }

    if let Err(e) = send_cert_to_station(&mut session, &usb_keys.pq_cert, "usb-pq").await {
        log::error!("Failed to load certificate on the station: {e}");
        session.close().await;
        return Err(String::from("Connection error"));
    }

    session.close().await;

    Ok(String::from("true"))
}

/// This function update a Keysas station using apt
#[command]
async fn update(ip: String) -> bool {
    let private_key = match get_ssh() {
        Ok((_, private)) => private,
        Err(e) => {
            log::error!("Failed to get private key: {e}");
            return false;
        }
    };

    let host = format!("{}{}", ip.trim(), ":22");
    log::error!("Rust will try updating host: {host}");

    // Connect to the host
    let mut session = match connect_key(&ip, &private_key).await {
        Ok(s) => s,
        Err(e) => {
            log::error!("Failed to open ssh connection with station: {e}");
            return false;
        }
    };

    match session_exec(
        &mut session,
        &String::from(
            "sudo /usr/bin/apt update && sudo /usr/bin/apt -y dist-upgrade && sudo /bin/systemctl reboot ",
        ),
    )
    .await
    {
        Ok(_) => {
            log::info!("Trying to update and rebooting...");
        }
        Err(why) => {
            log::error!("Error while updating: {why:?}");
            session.close().await;
            return false;
        }
    }
    session.close().await;
    true
}

/// This function reboot a Keysas station using systemctl
#[command]
async fn reboot(ip: String) -> bool {
    let private_key = match get_ssh() {
        Ok((_, private)) => private,
        Err(e) => {
            log::error!("Failed to get private key: {e}");
            return false;
        }
    };
    // Connect to the host
    let host = format!("{}{}", ip.trim(), ":22");
    log::info!("Rust will try rebooting host: {host}");
    let mut session = match connect_key(&ip, &private_key).await {
        Ok(s) => s,
        Err(e) => {
            log::error!("Failed to open ssh connection with station: {e}");
            return false;
        }
    };

    match session_exec(&mut session, &String::from("sudo /bin/systemctl reboot")).await {
        Ok(_) => {
            log::info!("Keysas station is rebooting !");
        }
        Err(why) => {
            log::error!("Rust error on open_exec: {why:?}");
            session.close().await;
            return false;
        }
    }
    session.close().await;
    true
}

/// This function shutdown a Keysas station using systemctl
#[command]
async fn shutdown(ip: String) -> bool {
    let private_key = match get_ssh() {
        Ok((_, private)) => private,
        Err(e) => {
            log::error!("Failed to get private key: {e}");
            return false;
        }
    };
    // Connect to the host
    let mut session = match connect_key(&ip, &private_key).await {
        Ok(s) => s,
        Err(e) => {
            log::error!("Failed to open ssh connection with station: {e}");
            return false;
        }
    };
    match session_exec(&mut session, &String::from("sudo /bin/systemctl poweroff")).await {
        Ok(_) => {
            log::info!("Keysas station is shutting down.");
            session.close().await;
        }
        Err(why) => {
            log::error!("Rust error on open_exec: {why:?}");
            session.close().await;
            return false;
        }
    }

    true
}

/// This function export the SSH pubkey to a Keysas station
/// Monitoring a Keysas station won't work until this has been done.
#[command]
async fn export_sshpubkey(ip: String) -> bool {
    let public_key = match get_ssh() {
        Ok((public, _)) => public,
        Err(e) => {
            log::error!("Failed to get private key: {e}");
            return false;
        }
    };
    log::info!("Exporting public SSH key to {ip:?}");
    // Connect to the host
    let mut session = match connect_pwd(&ip).await {
        Ok(s) => s,
        Err(e) => {
            log::error!("Failed to open ssh connection with station: {e}");
            return false;
        }
    };

    match session_upload(
        &mut session,
        public_key.trim(),
        &String::from("/home/keysas/.ssh/authorized_keys"),
    )
    .await
    {
        Ok(_) => {
            log::info!("authorized_keys successfully s-copied !");
        }
        Err(e) => {
            log::error!("Rust error on upload: {e:?}");
            session.close().await;
            return false;
        }
    }

    // Once the SSH has been copied, disable password authentication
    match session_exec(
        &mut session,
        &String::from(
            "if grep -q '^[[:space:]]*PasswordAuthentication' /etc/ssh/sshd_config && grep -v '^[[:space:]]*#' /etc/ssh/sshd_config | grep -q 'PasswordAuthentication'; then \
                sudo sed -i '/^[[:space:]]*PasswordAuthentication/s/.*/PasswordAuthentication no/' /etc/ssh/sshd_config; \
             else \
                echo 'PasswordAuthentication no' | sudo tee -a /etc/ssh/sshd_config > /dev/null; \
             fi && sudo systemctl restart sshd",
        ),
    )
    .await
    {
        Ok(res) => {
            log::debug!("Command output: {}", String::from_utf8(res).unwrap());
            log::info!("Password authentication has been disabled.");
            session.close().await;
            true
        }
        Err(e) => {
            log::error!("Rust error on open_exec: {e:?}");
            session.close().await;
            false
        }
    }
}

/// This command test if a given station is connected or not
/// The function returns a boolean indicating the station status or an error
#[command]
async fn is_alive(name: String) -> Result<bool, String> {
    if name.chars().count() == 0 {
        log::warn!(" is_alive: Name must not be empty");
        return Ok(false);
    }

    let private_key = match get_ssh() {
        Ok((_, private)) => private,
        Err(e) => {
            log::error!("Failed to get private key: {e}");
            return Err(String::from("Store error"));
        }
    };

    let ip = match get_station_ip_by_name(&name) {
        Ok(ip) => ip,
        Err(e) => {
            log::error!("Failed to get station ip: {e}");
            return Err(String::from("Store error"));
        }
    };

    // Connect to the host
    let mut session = match connect_key(&ip, &private_key).await {
        Ok(s) => s,
        Err(e) => {
            log::error!("Failed to open ssh connection with station: {e}");
            return Err(String::from("Store error"));
        }
    };
    match session_exec(&mut session, &String::from("/bin/systemctl status keysas")).await {
        Ok(_) => {
            log::info!("Keysas is alive.");
        }
        Err(why) => {
            log::error!("Cannot execute command status: {why:?}");
            session.close().await;
            return Err(String::from("Store error"));
        }
    }
    session.close().await;
    Ok(true)
}

// This function sign a USB device using firmware information
#[command]
async fn sign_key(password: String) -> bool {
    let (device, vendor, model, revision, serial) = match watch_new_usb() {
        Ok(dev) => dev,
        Err(e) => {
            log::error!("Error while looking for new USB device: {e}");
            return false;
        }
    };
    match sign_usb(
        &device, &vendor, &model, &revision, &serial, "out", &password,
    ) {
        Ok(o) => o,
        Err(e) => {
            log::error!("Error while looking for new USB device: {e}");
            return false;
        }
    };
    true
}

#[command]
async fn validate_privatekey(public_key: String, private_key: String) -> bool {
    Path::new(&public_key.trim()).is_file() && Path::new(&private_key.trim()).is_file()
}

#[command]
async fn validate_rootkey(root_key: String) -> bool {
    Path::new(&root_key.trim()).is_file()
}

/// Generate a new PKI in an empty directory
///
/// # Arguments
/// * `org_name` - String containing the organisation name of the PKI
/// * `org_unit` - String containing the organisational unit of the PKI
/// * `country` - String containing the country name of the PKI
/// * `validity` - String representation of the number of days of validity for PKI root keys
/// * `admin_pwd` - String containing the PKI administrator password
/// * `pki_dir` - String containing the path the PKI directory
///
/// # Return
/// Return a result containing an error message if any
#[command]
async fn generate_pki_in_dir(
    org_name: String,
    org_unit: String,
    country: String,
    validity: String,
    admin_pwd: String,
    pki_dir: String,
) -> Result<String, String> {
    // Validate user inputs
    let infos = match CertificateFields::from_fields(
        Some(&org_name),
        Some(&org_unit),
        Some(&country),
        None,
        Some(&validity),
    ) {
        Ok(i) => i,
        Err(_) => {
            log::error!("Failed to validate user input");
            return Err(String::from("Invalid user input"));
        }
    };
    // Validate pki_dir path and directory hierachy
    if let Err(e) = create_pki_dir(&pki_dir) {
        log::error!("Failed to create PKI directory: {e}");
        return Err(String::from("Invalid PKI directory path"));
    }
    // Save PKI configuration
    if let Err(e) = set_pki_config(&pki_dir, &infos) {
        log::error!("Failed to save PKI configuration: {e}");
        return Err(String::from("Store error"));
    }

    // Generate root key and save them in PKCS12 format
    let root_keys = match HybridKeyPair::generate_root(&infos) {
        Ok(kp) => kp,
        Err(e) => {
            log::error!("Failed to generate PKI root keys: {e}");
            return Err(String::from("PKI error"));
        }
    };

    // Save keys
    if let Err(e) = root_keys.save(
        PKI_ROOT_KEY_NAME,
        Path::new(&(pki_dir.to_owned() + PKI_ROOT_SUB_DIR)),
        Path::new(&(pki_dir.to_owned() + PKI_ROOT_SUB_DIR)),
        &admin_pwd,
    ) {
        log::error!("Failed to save root key to disk: {e}");
        return Err(String::from("PKI error"));
    }

    // Generate keysas station intermediate CA key pair
    let ca_infos = match CertificateFields::from_fields(None, None, None, Some("Station CA"), None)
    {
        Ok(i) => i,
        Err(e) => {
            log::error!("Failed to generate station CA name field: {e}");
            return Err(String::from("PKI error"));
        }
    };
    let ca_name = match ca_infos.generate_dn() {
        Ok(n) => n,
        Err(e) => {
            log::error!("Failed to generate distinguished name for station CA: {e}");
            return Err(String::from("PKI error"));
        }
    };
    let st_ca_keys =
        match HybridKeyPair::generate_signed_keypair(&root_keys, &ca_name, &infos, false) {
            Ok(kp) => kp,
            Err(e) => {
                log::error!("Failed to generate intermediate CA for station: {e}");
                return Err(String::from("PKI error"));
            }
        };
    // Save keys
    log::debug!("{:?}", Path::new(&(pki_dir.to_owned() + ST_CA_SUB_DIR)));
    if let Err(e) = st_ca_keys.save(
        ST_CA_KEY_NAME,
        Path::new(&(pki_dir.to_owned() + ST_CA_SUB_DIR)),
        Path::new(&(pki_dir.to_owned() + ST_CA_SUB_DIR)),
        &admin_pwd,
    ) {
        log::error!("Failed to save station CA key to disk: {e}");
        return Err(String::from("PKI error"));
    }

    // Generate USB signing key pair
    let usb_infos = match CertificateFields::from_fields(None, None, None, Some("USB admin"), None)
    {
        Ok(i) => i,
        Err(e) => {
            log::error!("Failed to generate station CA name field: {e}");
            return Err(String::from("PKI error"));
        }
    };
    let usb_name = match usb_infos.generate_dn() {
        Ok(n) => n,
        Err(e) => {
            log::error!("Failed to generate distinguished name for station CA: {e}");
            return Err(String::from("PKI error"));
        }
    };
    let usb_keys = match HybridKeyPair::generate_signed_keypair(&root_keys, &usb_name, &infos, true)
    {
        Ok(kp) => kp,
        Err(e) => {
            log::error!("Failed to generate USB signing key pair: {e}");
            return Err(String::from("PKI error"));
        }
    };
    // Save keys
    log::debug!(
        "{:?}",
        Path::new(&(pki_dir.to_owned() + "/" + USB_CA_SUB_DIR + "/"))
    );
    if let Err(e) = usb_keys.save(
        USB_CA_KEY_NAME,
        Path::new(&(pki_dir.to_owned() + USB_CA_SUB_DIR)),
        Path::new(&(pki_dir + USB_CA_SUB_DIR)),
        &admin_pwd,
    ) {
        log::error!("Failed to save station CA key to disk: {e}");
        return Err(String::from("PKI error"));
    }

    Ok(String::from("PKI created"))
}

/// Get the PKI configuration from database.
#[command]
async fn get_pki_config() -> Result<CertificateFields, String> {
    let cert_fields = match get_pki_info() {
        Ok(list) => list,
        Err(e) => {
            log::error!("Cannot get PKI configuration in database: {e}.");
            return Err(String::from("Cannot get PKI configuration in database"));
        }
    };
    Ok(cert_fields)
}

/// Get the PKI path from database.
#[command]
async fn get_pki_path() -> Result<String, String> {
    let dir = match get_pki_dir() {
        Ok(d) => d,
        Err(e) => {
            log::error!("Cannot get PKI directory in database: {e}.");
            return Err(String::from("Cannot get PKI directory in database"));
        }
    };
    Ok(dir)
}

/// Revoke a signed USB device.
#[command]
async fn revoke_usb() -> bool {
    let (device, _vendor, _model, _revision, _serial) = match watch_new_usb() {
        Ok(dev) => dev,
        Err(e) => {
            log::error!("Error while looking for new USB device: {e}");
            return false;
        }
    };
    match revoke_device(&device) {
        Ok(d) => d,
        Err(e) => {
            log::error!("Cannot revoke device: {e}.");
            return false;
        }
    };
    true
}

/// Load a saved PKI into database.
#[command]
async fn restore_pki(base_path: String, admin_pwd: String) -> bool {
    let base = base_path.to_owned();
    match check_restore_pki(&base, &admin_pwd).await {
        Ok(d) => d,
        Err(e) => {
            log::error!("Cannot restore PKI in database: {e}.");
            return false;
        }
    };
    true
}

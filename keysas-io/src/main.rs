// SPDX-License-Identifier: GPL-3.0-only
/*
 * The "keysas-io".
 *
 * (C) Copyright 2019-2025 Stephane Neveu
 *
 * This file is the main file for udev management.
 */

#![feature(atomic_from_mut)]
#![feature(str_split_remainder)]
#![feature(random)]

extern crate libc;
extern crate regex;
extern crate udev;

use anyhow::anyhow;
use base64::{Engine as _, engine::general_purpose};
use clap::{Arg, Command as Clap_Command, crate_version};
use log::{debug, error, info, warn};
use regex::Regex;
use std::fs::{self, create_dir_all};
use std::path::PathBuf;
use std::random::random;
use std::thread as sthread;
use std::{ffi::OsStr, net::TcpListener, thread::spawn};
use tungstenite::{
    Message, accept_hdr,
    handshake::server::{Request, Response},
};
use udev::Event;
use walkdir::WalkDir;

extern crate proc_mounts;
extern crate serde;
extern crate serde_json;
extern crate sys_mount;

#[macro_use]
extern crate serde_derive;

use crate::errors::*;
use bytemuck::cast_slice;
use ed25519_dalek::Signature as SignatureDalek;
use keysas_lib::init_logger;
use keysas_lib::keysas_key::PublicKeys;
use keysas_lib::keysas_key::{KeysasHybridPubKeys, KeysasHybridSignature};
use kv::Config as kvConfig;
use kv::*;
use libc::{c_int, c_short, c_ulong, c_void};
use oqs::sig::{Algorithm, Sig};
use proc_mounts::MountIter;
use std::fs::File;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::{Read, Write as wr};
use std::ops::Deref;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::ptr;
use std::str;
use std::sync::Arc;
use std::time::Duration;
use sys_mount::unmount;
use sys_mount::{FilesystemType, Mount, MountFlags, SupportedFilesystems, Unmount, UnmountFlags};
use yubico_manager::Yubico;
use yubico_manager::config::Config;
use yubico_manager::config::{Mode, Slot};

mod errors;

#[allow(non_camel_case_types)]
#[repr(C)]
struct pollfd {
    fd: c_int,
    events: c_short,
    revents: c_short,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct sigset_t {
    __private: c_void,
}

#[allow(non_camel_case_types)]
type nfds_t = c_ulong;

const POLLIN: c_short = 0x0001;

unsafe extern "C" {
    fn ppoll(
        fds: *mut pollfd,
        nfds: nfds_t,
        timeout_ts: *mut libc::timespec,
        sigmask: *const sigset_t,
    ) -> c_int;
}

#[derive(Serialize, Deserialize, Debug)]
struct Yubistruct {
    active: bool,
    yubikeys: Vec<String>,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct Usbkeys {
    usb_in: Vec<String>,
    usb_out: Vec<String>,
    usb_undef: Vec<String>,
    yubikeys: Yubistruct,
}

trait StrExt {
    fn remove_last(&self) -> &str;
}

impl StrExt for str {
    fn remove_last(&self) -> &str {
        match self.char_indices().next_back() {
            Some((i, _)) => &self[..i],
            None => self,
        }
    }
}

// Const as we do not want them to be user modifyied
const TMP_DIR: &str = "/var/local/tmp/";
const SAS_IN: &str = "/var/local/in/";
const SAS_OUT: &str = "/var/local/out/";
const LOCK: &str = "/var/local/in/.lock";
const FIDO_DB: &str = "/etc/keysas/fido_db";
const VAR_LOCK_DIR: &str = "/var/lock/keysas/";
const WORKING_IN_FILE: &str = "/var/lock/keysas/keysas-in";
const WORKING_OUT_FILE: &str = "/var/lock/keysas/keysas-out";

fn list_yubikey() -> Vec<String> {
    let mut yubi = Yubico::new();
    let mut yubikey_vector = Vec::new();

    if let Ok(device) = yubi.find_yubikey() {
        debug!(
            "Vendor ID: {:?}, Product ID {:?}.",
            device.vendor_id, device.product_id
        );
        let concat = format!("{:?}/{:?}", device.vendor_id, device.product_id);
        yubikey_vector.push(concat);
    } else {
        debug!("Fido2: Yubikey not present.");
    }
    yubikey_vector
}

fn hmac_challenge() -> Option<String> {
    // TODO: Must be improved to manage all cases
    if Path::new(FIDO_DB).is_dir() {
        let mut yubi = Yubico::new();

        if let Ok(device) = yubi.find_yubikey() {
            info!(
                "New Yubico found: Vendor ID is {:?}, Product ID is {:?}",
                device.vendor_id, device.product_id
            );

            let config = Config::default_config()
                .set_vendor_id(device.vendor_id)
                .set_product_id(device.product_id)
                .set_variable_size(true)
                .set_mode(Mode::Sha1)
                .set_slot(Slot::Slot2);

            // Challenge can not be greater than 64 bytes
            let mut challenge: [u128; 4] = [0; 4];
            for item in &mut challenge {
                *item = random(..);
            }
            let casted_challenge = cast_slice(&challenge);
            // In HMAC Mode, the result will always be the SAME for the SAME provided challenge
            match yubi.challenge_response_hmac(casted_challenge, config) {
                Ok(hmac_result) => {
                    let v: &[u8] = hmac_result.deref();
                    let hex_string = hex::encode(v);

                    let cfg = kvConfig::new(FIDO_DB);

                    // Open the key/value store
                    match Store::new(cfg) {
                        Ok(store) => match store.bucket::<String, String>(Some("Keysas")) {
                            Ok(enrolled_yubikeys) => match enrolled_yubikeys.get(&hex_string) {
                                Ok(y) => y,
                                Err(why) => {
                                    error!("Error while getting yubikey value: {why:?}");
                                    None
                                }
                            },
                            Err(why) => {
                                error!("Error while accessing the Bucket: {why:?}");
                                None
                            }
                        },

                        Err(why) => {
                            error!("Error while accessing the store: {why:?}");
                            None
                        }
                    }
                }
                Err(why) => {
                    error!("Error while performing hmac challenge {why:?}");
                    None
                }
            }
        } else {
            warn!("Yubikey not found, please insert a Yubikey.");
            None
        }
    } else {
        error!("Error: Database Fido database wasn't found.");
        None
    }
}

fn get_signature(device: &str) -> Result<KeysasHybridSignature> {
    let offset = 512;
    let mut f = File::options()
        .read(true)
        .open(device)
        .context("Cannot open the USB device to verify the signature.")?;
    // Seeking for hybrid signature
    let mut buf = [0u8; 4];
    f.seek(SeekFrom::Start(offset))?;
    f.read_exact(&mut buf)?;
    let signature_size = u32::from_be_bytes(buf);
    // Size must not be > 7684 bytes LBA-MBR (8196-512)
    if signature_size > 7684_u32 {
        return Err(anyhow!("Invalid length for signature"));
    }
    // Now read the signature size only
    let mut buffer = vec![0u8; signature_size.try_into()?];
    log::debug!("Allocated buffer size for signature is {}", buf.len());
    f.read_exact(&mut buffer)?;
    let buf_str = String::from_utf8(buffer.to_vec())?;

    let mut signatures = buf_str.split('|');
    if signatures.clone().count() != 2 {
        return Err(anyhow!("Invalid number of certificates"));
    }
    let s_cl = match signatures.next() {
        Some(cl) => cl,
        None => return Err(anyhow!("Cannot parse Classic signature from USB device")),
    };

    let s_cl_decoded = match general_purpose::STANDARD.decode(s_cl) {
        Ok(cl) => cl,
        Err(e) => {
            return Err(anyhow!(
                "Cannot decode base64 Classic signature from bytes: {e}"
            ));
        }
    };

    let s_pq = match signatures.remainder() {
        Some(pq) => pq,
        None => return Err(anyhow!("Cannot parse PQ signature from USB device")),
    };

    let s_pq_decoded = match general_purpose::STANDARD.decode(s_pq) {
        Ok(pq) => pq,
        Err(e) => return Err(anyhow!("Cannot decode base64 PQ signature from bytes: {e}")),
    };
    let mut s_cl_decoded_casted: [u8; 64] = [0u8; 64];
    if s_cl_decoded.len() == 64_usize {
        s_cl_decoded_casted.copy_from_slice(&s_cl_decoded);
    } else {
        return Err(anyhow!(" Signature is not 64 bytes long"));
    }

    let sig_dalek = SignatureDalek::from_bytes(&s_cl_decoded_casted);
    oqs::init();
    let pq_scheme = match Sig::new(Algorithm::MlDsa87) {
        Ok(pq_s) => pq_s,
        Err(e) => return Err(anyhow!("Cannot construct new ML-DSA87 algorithm: {e}")),
    };

    let sig_pq = match pq_scheme.signature_from_bytes(&s_pq_decoded) {
        Some(sig) => sig,
        None => return Err(anyhow!("Cannot parse PQ signature from bytes")),
    };
    Ok(KeysasHybridSignature {
        classic: sig_dalek,
        pq: sig_pq.to_owned(),
    })
}

fn is_signed(
    device: &str,
    ca_cert_cl: &str,
    ca_cert_pq: &str,
    id_vendor_id: &str,
    id_model_id: &str,
    id_revision: &str,
    id_serial: &str,
) -> bool {
    debug!("Checking signature for device: {device}");
    //Getting both pubkeys for certs
    let opt_pubkeys = match KeysasHybridPubKeys::get_pubkeys_from_certs(ca_cert_cl, ca_cert_pq) {
        Ok(o) => o,
        Err(e) => {
            warn!("Cannot get pubkeys from certs: {e}");
            return false;
        }
    };
    let pubkeys = match opt_pubkeys {
        Some(p) => p,
        None => {
            error!("No pubkeys found in certificates, cannot build KeysasHybridPubKeys");
            return false;
        }
    };

    //Let's read the hybrid signature from the device
    let signatures = match get_signature(device.remove_last()) {
        Ok(signature) => {
            info!("Reading signature from device: {:?}", device.remove_last());
            signature
        }
        Err(e) => {
            error!("Cannot parse signature on the device: {e}");
            return false;
        }
    };
    let data = format!(
        "{}/{}/{}/{}/{}",
        id_vendor_id, id_model_id, id_revision, id_serial, "out"
    );
    match KeysasHybridPubKeys::verify_key_signatures(data.as_bytes(), signatures, pubkeys) {
        Ok(_) => {
            info!("USB device is signed");
            true
        }
        Err(e) => {
            info!("Signatures are not matching on USB device: {e}");
            false
        }
    }
}

fn copy_device_in(device: &Path) -> Result<()> {
    let dir = tempfile::tempdir()?;
    let mount_point = dir.path();
    info!("Unsigned USB device {device:?} will be mounted on path: {mount_point:?}");
    let supported = SupportedFilesystems::new()?;
    let mount_result = Mount::builder()
        .fstype(FilesystemType::from(&supported))
        .flags(MountFlags::RDONLY | MountFlags::NOSUID | MountFlags::NOEXEC | MountFlags::NODEV)
        .mount(device, mount_point);
    match mount_result {
        Ok(mount) => {
            // Copying file to the mounted device.
            info!("Unsigned device is mounted on: {mount_point:?}");
            copy_files_in(&mount_point.to_path_buf())?;
            // Make the mount temporary, so that it will be unmounted on drop.
            let _mount = mount.into_unmount_drop(UnmountFlags::DETACH);
        }
        Err(why) => {
            error!("Failed to mount unsigned device: {why}");
            let reg = Regex::new(r"/tmp/\.tmp.*")?;
            for mount in MountIter::new()? {
                let mnt = mount.as_ref().unwrap().dest.to_str().unwrap();
                if reg.is_match(mnt) {
                    debug!("Will umount: {mnt}");
                }
            }
        }
    }
    Ok(())
}

fn move_device_out(device: &Path) -> Result<PathBuf> {
    let dir = tempfile::tempdir()?;
    let mount_point = dir.path();
    info!("Signed USB device {device:?} will be mounted on path: {mount_point:?}");
    let supported = SupportedFilesystems::new()?;
    let mount_result = Mount::builder()
        .fstype(FilesystemType::from(&supported))
        .flags(MountFlags::NOEXEC | MountFlags::NOSUID | MountFlags::NODEV)
        .mount(device, mount_point);
    match mount_result {
        Ok(mount) => {
            // Moving files to the mounted device.
            info!("Temporary out mount point for signed key: {mount_point:?}");
            move_files_out(&mount_point.to_path_buf())?;
            // Make the mount temporary, so that it will be unmounted on drop.
            let _mount = mount.into_unmount_drop(UnmountFlags::DETACH);
        }
        Err(why) => {
            error!("Failed to mount signed device: {why}");
        }
    }
    Ok(mount_point.to_path_buf())
}

fn copy_files_in(mount_point: &PathBuf) -> Result<()> {
    File::create(LOCK)?;
    std::thread::scope(|s| {
        for e in WalkDir::new(mount_point).into_iter().filter_map(|e| e.ok()) {
            if e.metadata()
                .expect("Cannot get metadata for file.")
                .is_file()
            {
                // SAFETY: Thread should not panic as we test everything using match{}
                s.spawn(move || {
                         debug!("New entry path found: {}.", e.path().display());
                         let path_to_read = match e.path().to_str() {
                             Some(p) => p,
                             None => {
                                 error!("Cannot convert path to string.");
                                 return;
                             }
                         };
                         let entry = e.file_name().to_string_lossy();
                         let entry_cleaned = str::replace(&entry, "?", "-");
                         let path_to_write = format!(
                             "{}{}",
                             SAS_IN,
                             diacritics::remove_diacritics(&entry_cleaned)
                         );
                         let path_to_tmp = format!(
                             "{}{}",
                             TMP_DIR,
                             diacritics::remove_diacritics(&entry_cleaned)
                         );

                         // Create a tmp dir to be able to rename files later
                         let tmp = TMP_DIR.trim_end_matches("/");
                         let tmp = Path::new(tmp);

                         if tmp.exists() {
                            if tmp.is_dir() {
                                debug!("tmp directory already exists.");
                            } else {
                                error!("A file with the same name as the directory already exists: {TMP_DIR}");
                                return;
                            }
                        } else {
                             match fs::create_dir(tmp) {
                                 Ok(_)=> info!("Creating tmp directory for writing incoming files !"),
                                 Err(e) => error!("Cannot create tmp directory: {e:?}"),
                             }
                         }
                         match fs::metadata(path_to_read) {
                             Ok(mtdata) => {
                                 if Path::new(&path_to_read).exists() && !mtdata.is_dir() {
                                     match fs::copy(path_to_read, &path_to_tmp) {
                                         Ok(_) => {
                                             info!("File {path_to_read} copied to {path_to_tmp}.");
                                         if fs::rename(&path_to_tmp, path_to_write).is_ok() { info!("File {} moved to sas-in.", &path_to_tmp) }
                                     },
                                         Err(e) => {
                                             error!(
                                                 "Error while copying file {path_to_read}: {e:?}"
                                             );
                                             let report =
                                                 format!("{}{}", path_to_write, ".ioerror");
                                             let mut report = match File::create(&report) {
                                                 Ok(r) => {
                                                    info!("io-error report file created.");
                                                    r
                                                },
                                                 Err(why) => {
                                                     error!(
                                                         "Failed to create io-error report {report:?}: {why}"
                                                     );
                                                     return;
                                                 }
                                             };
                                             match writeln!(
                                                 report,
                                                 "Error while copying file: {e:?}"
                                             ) {
                                                 Ok(_) => info!("io-error report file updated."),
                                                 Err(why) => {
                                                     error!(
                                                     "Failed to write into io-error report {report:?}: {why}"
                                                 );
                                                 }
                                             }
                                             match unmount(mount_point, UnmountFlags::DETACH) {
                                                 Ok(()) => {
                                                     debug!(
                                                         "Early removing mount point: {mount_point:?}"
                                                     )
                                                 }
                                                 Err(why) => {
                                                     error!(
                                                         "Failed to unmount {mount_point:?}: {why}"
                                                     );
                                                 }
                                             }
                                         }
                                     }
                                 }
                             }
                             Err(why) => error!(
                                 "Thread error: Cannot get metadata for file {path_to_read:?}: {why:?}. Terminating thread..."
                             ),
                         };
             });
            }
        }
    });
    info!("Incoming files copied sucessfully, unlocking.");
    if Path::new(LOCK).exists() {
        fs::remove_file(LOCK)?;
    }
    Ok(())
}

fn move_files_out(mount_point: &PathBuf) -> Result<()> {
    let dir = fs::read_dir(SAS_OUT)?;
    for entry in dir {
        let entry = entry?;
        debug!("New entry found: {:?}.", entry.file_name());

        let path_to_write = format!(
            "{}{}{}",
            &mount_point.to_string_lossy(),
            "/",
            diacritics::remove_diacritics(&entry.file_name().to_string_lossy())
        );
        let path_to_read = format!(
            "{}{}",
            SAS_OUT,
            entry.file_name().to_string_lossy().into_owned()
        );
        if !fs::metadata(&path_to_read)?.is_dir() {
            match fs::copy(&path_to_read, path_to_write) {
                Ok(_) => info!("Copying file: {path_to_read} to signed device."),
                Err(e) => {
                    error!("Error while copying file to signed device {path_to_read}: {e:?}");
                    match unmount(mount_point, UnmountFlags::DETACH) {
                        Ok(()) => debug!("Early removing mount point: {mount_point:?}"),
                        Err(why) => {
                            error!("Failed to unmount {mount_point:?}: {why}");
                        }
                    }
                }
            }
            fs::remove_file(&path_to_read)?;
            info!("Removing file: {path_to_read}.");
        }
    }
    info!("Moving files to outgoing device done.");
    Ok(())
}

// Function done for keysas-backend daemon
// Keysas-backend shows the final user
// if the station is busy or not.
// Simple files are created and are watched
// as I do not want any communications
// between these daemons.
fn busy_in() -> Result<(), anyhow::Error> {
    if !Path::new(VAR_LOCK_DIR).exists() {
        create_dir_all(VAR_LOCK_DIR)?;
    } else if Path::new(WORKING_OUT_FILE).exists() {
        fs::remove_file(WORKING_OUT_FILE)?;
    } else if !Path::new(WORKING_IN_FILE).exists() {
        File::create(WORKING_IN_FILE)?;
    } else {
        debug!("No WORKING_FILES was found.")
    }
    Ok(())
}

fn busy_out() -> Result<(), anyhow::Error> {
    if !Path::new(VAR_LOCK_DIR).exists() {
        create_dir_all(VAR_LOCK_DIR)?;
    } else if Path::new(WORKING_IN_FILE).exists() {
        fs::remove_file(WORKING_IN_FILE)?;
    } else if !Path::new(WORKING_OUT_FILE).exists() {
        File::create(WORKING_OUT_FILE)?;
    } else {
        debug!("No WORKING_FILES was found.")
    }
    Ok(())
}

fn ready_in() -> Result<(), anyhow::Error> {
    if Path::new(WORKING_IN_FILE).exists() {
        fs::remove_file(WORKING_IN_FILE)?;
    }
    Ok(())
}

fn ready_out() -> Result<(), anyhow::Error> {
    if Path::new(WORKING_OUT_FILE).exists() {
        fs::remove_file(WORKING_OUT_FILE)?;
    }
    Ok(())
}

fn get_attr_udev(event: Event) -> Result<String, anyhow::Error> {
    let id_vendor_id = event
        .property_value(
            OsStr::new("ID_VENDOR_ID")
                .to_str()
                .ok_or_else(|| anyhow!("Cannot convert ID_VENDOR_ID to str."))?,
        )
        .ok_or_else(|| anyhow!("Cannot get ID_VENDOR_ID from event."))?;
    let id_model_id = event
        .property_value(
            OsStr::new("ID_MODEL_ID")
                .to_str()
                .ok_or_else(|| anyhow!("Cannot convert ID_MODEL_ID to str."))?,
        )
        .ok_or_else(|| anyhow!("Cannot get ID_MODEL_ID from event."))?;
    let id_revision = event
        .property_value(
            OsStr::new("ID_REVISION")
                .to_str()
                .ok_or_else(|| anyhow!("Cannot convert ID_REVISION to str."))?,
        )
        .ok_or_else(|| anyhow!("Cannot get ID_REVISION from event."))?;

    let product = format!(
        "{}/{}/{}",
        id_vendor_id.to_string_lossy(),
        id_model_id.to_string_lossy(),
        id_revision.to_string_lossy()
    );
    Ok(product)
}

fn main() -> Result<()> {
    let matches = Clap_Command::new("keysas-io")
        .version(crate_version!())
        .author("Stephane N")
        .about("keysas-io for USB devices verification.")
        .arg(
            Arg::new("ca-cert-cl")
                .short('c')
                .long("classiccacert")
                .value_name("/etc/keysas/usb-ca-cl.pem")
                .value_parser(clap::value_parser!(String))
                .default_value("/etc/keysas/usb-ca-cl.pem")
                .help("The path to Classic CA certificate (Default is /etc/keysas/usb-ca-cl.pem)."),
        )
        .arg(
            Arg::new("ca-cert-pq")
                .short('p')
                .long("pqcacert")
                .value_name("/etc/keysas/usb-ca-pq.pem")
                .value_parser(clap::value_parser!(String))
                .default_value("/etc/keysas/usb-ca-pq.pem")
                .help("The path to post-quantum CA certificate (Default is /etc/keysas/usb-ca-pq.pem)."),
        )
        .arg(
            Arg::new("yubikey")
                .short('y')
                .long("yubikey")
                .value_name("false")
                .default_value("false")
                .value_parser(clap::value_parser!(String))
                .help("Activate the user authentication via Yubikeys."),
        )
        .get_matches();

    let ca_cert_cl = matches.get_one::<String>("ca-cert-cl").unwrap();
    let ca_cert_cl = ca_cert_cl.to_string();
    let ca_cert_cl = Arc::new(ca_cert_cl);
    let ca_cert_pq = matches.get_one::<String>("ca-cert-pq").unwrap();
    let ca_cert_pq = ca_cert_pq.to_string();
    let ca_cert_pq = Arc::new(ca_cert_pq);
    let yubikey = matches.get_one::<String>("yubikey").unwrap();
    let yubikey = yubikey
        .parse::<bool>()
        .context("Cannot convert YUBIKEY value string into boolean !")?;

    init_logger();
    let server = TcpListener::bind("127.0.0.1:3013")?;
    for stream in server.incoming() {
        let ca_cert_cl = Arc::clone(&ca_cert_cl);
        let ca_cert_pq = Arc::clone(&ca_cert_pq);
        spawn(move || -> Result<()> {
            let callback = |_req: &Request, response: Response| {
                info!("keysas-io: Received a new websocket handshake.");
                Ok(response)
            };
            let mut websocket = accept_hdr(stream?, callback)?;

            let socket = udev::MonitorBuilder::new()?
                .match_subsystem("block")?
                .listen()?;

            let mut fds = [pollfd {
                fd: socket.as_raw_fd(),
                events: POLLIN,
                revents: 0,
            }];
            let mut keys_in = vec![];
            let mut keys_out = vec![];
            let mut keys_undef = vec![];
            let yubi: Yubistruct = Yubistruct {
                active: yubikey,
                yubikeys: list_yubikey(),
            };
            let keys: Usbkeys = Usbkeys {
                usb_in: Vec::new(),
                usb_out: Vec::new(),
                usb_undef: Vec::new(),
                yubikeys: yubi,
            };
            let serialized = serde_json::to_string(&keys)?;
            websocket.send(Message::Text(serialized.into()))?;

            loop {
                let result = unsafe {
                    ppoll(
                        fds[..].as_mut_ptr(),
                        fds.len() as nfds_t,
                        ptr::null_mut(),
                        ptr::null(),
                    )
                };

                if result < 0 {
                    error!("Error: ppoll error, result is < 0.");
                }

                let event = match socket.iter().next() {
                    Some(evt) => evt,
                    None => {
                        sthread::sleep(Duration::from_millis(10));
                        continue;
                    }
                };

                info!("New USB event type detected: {:?}", event.event_type());
                info!("action: {:?}", event.action());
                info!(
                    "property_value: {:?}",
                    event.property_value(
                        OsStr::new("DEVTYPE")
                            .to_str()
                            .ok_or_else(|| anyhow!("Cannot convert DEVTYPE to str."))?
                    )
                );
                if event.action() == Some(OsStr::new("add"))
                    && ((event.property_value(
                        OsStr::new("DEVTYPE")
                            .to_str()
                            .ok_or_else(|| anyhow!("Cannot convert DEVTYPE to str."))?,
                    ) == Some(OsStr::new("partition")))
                        || (event.property_value(
                            OsStr::new("DEVTYPE")
                                .to_str()
                                .ok_or_else(|| anyhow!("Cannot convert DEVTYPE to str."))?,
                        ) == Some(OsStr::new("disk"))))
                {
                    let yubi: Yubistruct = Yubistruct {
                        active: yubikey,
                        yubikeys: list_yubikey(),
                    };
                    let keys: Usbkeys = Usbkeys {
                        usb_in: Vec::new(),
                        usb_out: Vec::new(),
                        usb_undef: Vec::new(),
                        yubikeys: yubi,
                    };
                    let serialized = serde_json::to_string(&keys)?;
                    websocket.send(Message::Text(serialized.into()))?;

                    let id_vendor_id = event
                        .property_value(
                            OsStr::new("ID_VENDOR_ID")
                                .to_str()
                                .ok_or_else(|| anyhow!("Cannot convert ID_VENDOR_ID to str."))?,
                        )
                        .ok_or_else(|| anyhow!("Cannot get ID_VENDOR_ID from event."))?;
                    let id_model_id = event
                        .property_value(
                            OsStr::new("ID_MODEL_ID")
                                .to_str()
                                .ok_or_else(|| anyhow!("Cannot convert ID_MODEL_ID to str."))?,
                        )
                        .ok_or_else(|| anyhow!("Cannot get ID_MODEL_ID from event."))?;
                    let id_revision = event
                        .property_value(
                            OsStr::new("ID_REVISION")
                                .to_str()
                                .ok_or_else(|| anyhow!("Cannot convert ID_REVISION to str."))?,
                        )
                        .ok_or_else(|| anyhow!("Cannot get ID_REVISION from event."))?;
                    let device = event
                        .property_value(
                            OsStr::new("DEVNAME")
                                .to_str()
                                .ok_or_else(|| anyhow!("Cannot get DEVNAME from event."))?,
                        )
                        .ok_or_else(|| anyhow!("Cannot get DEVNAME from event."))?;
                    let id_serial = event
                        .property_value(
                            OsStr::new("ID_SERIAL")
                                .to_str()
                                .ok_or_else(|| anyhow!("Cannot convert ID_SERIAL to str."))?,
                        )
                        .ok_or_else(|| anyhow!("Cannot get ID_SERIAL from event."))?;
                    error!(
                        "device: {:?}",
                        event
                            .device()
                            .parent()
                            .unwrap()
                            .property_value(OsStr::new("system_name"))
                    );
                    //for property in event.device().parent() {
                    //    for attr in property.attributes() {
                    //        println!("{:?}:{:?}", attr.name(),attr.value());
                    //        //println!("{:?} = {:?}", property.name(), property.value());
                    //}
                    //    }
                    info!("New USB device found: {}", device.to_string_lossy());
                    let product = format!(
                        "{}/{}/{}",
                        id_vendor_id.to_string_lossy(),
                        id_model_id.to_string_lossy(),
                        id_revision.to_string_lossy()
                    );

                    let id_vendor_id = id_vendor_id
                        .to_str()
                        .ok_or_else(|| anyhow!("Cannot convert id_vendor_id to str."))?;
                    let id_model_id = id_model_id
                        .to_str()
                        .ok_or_else(|| anyhow!("Cannot convert id_model_id to str."))?;
                    let id_revision = id_revision
                        .to_str()
                        .ok_or_else(|| anyhow!("Cannot convert id_revision to str."))?;
                    let device = device
                        .to_str()
                        .ok_or_else(|| anyhow!("Cannot convert device to str."))?;
                    let id_serial = id_serial
                        .to_str()
                        .ok_or_else(|| anyhow!("Cannot convert id_serial to str."))?;

                    let signed = is_signed(
                        device,
                        &ca_cert_cl,
                        &ca_cert_pq,
                        id_vendor_id,
                        id_model_id,
                        id_revision,
                        id_serial,
                    );
                    if !signed {
                        info!("Device signature is not valid !");
                        let keys_in_iter: Vec<String> = keys_in.clone().into_iter().collect();
                        warn!("keys_in_iter: {keys_in_iter:?}");
                        if !keys_in_iter.contains(&product) {
                            busy_in()?;
                            keys_in.push(product);
                            let yubi: Yubistruct = Yubistruct {
                                active: yubikey,
                                yubikeys: list_yubikey(),
                            };
                            let keys: Usbkeys = Usbkeys {
                                usb_in: keys_in.clone(),
                                usb_out: keys_out.clone(),
                                usb_undef: keys_undef.clone(),
                                yubikeys: yubi,
                            };
                            info!("DEVICE NOT VALID1: {}", &device);
                            let serialized = serde_json::to_string(&keys)?;
                            websocket.send(Message::Text(serialized.into()))?;
                            if yubikey {
                                match hmac_challenge() {
                                    Some(name) => {
                                        info!("HMAC challenge successfull for user: {name} !");
                                        copy_device_in(Path::new(&device))?;
                                        info!("Unsigned USB device done.");
                                        ready_in()?;
                                    }
                                    None => {
                                        warn!("No user found during HMAC challenge !");
                                        ready_in()?;
                                    }
                                };
                            } else {
                                info!("DEVICE NOT VALID2: {}", &device);
                                copy_device_in(Path::new(&device))?;
                                info!("Unsigned USB device done.");
                                ready_in()?;
                            }
                        } else if event.property_value(
                            OsStr::new("DEVTYPE")
                                .to_str()
                                .ok_or_else(|| anyhow!("Cannot convert DEVTYPE to str."))?,
                        ) == Some(OsStr::new("partition"))
                        {
                            busy_in()?;
                            //keys_in.push(product);
                            let yubi: Yubistruct = Yubistruct {
                                active: yubikey,
                                yubikeys: list_yubikey(),
                            };
                            let keys: Usbkeys = Usbkeys {
                                usb_in: keys_in.clone(),
                                usb_out: keys_out.clone(),
                                usb_undef: keys_undef.clone(),
                                yubikeys: yubi,
                            };
                            info!("DEVICE NOT VALID3: {}", &device);
                            let serialized = serde_json::to_string(&keys)?;
                            websocket.send(Message::Text(serialized.into()))?;
                            copy_device_in(Path::new(&device))?;
                            ready_in()?;
                            info!("Unsigned USB device done.");
                        }
                    //Signature ok so this is a out device
                    } else {
                        info!("USB device is signed.");
                        let keys_out_iter: Vec<String> = keys_out.clone().into_iter().collect();
                        if !keys_out_iter.contains(&product) {
                            busy_out()?;
                            keys_out.push(product);
                            let yubi: Yubistruct = Yubistruct {
                                active: yubikey,
                                yubikeys: list_yubikey(),
                            };
                            let keys: Usbkeys = Usbkeys {
                                usb_in: keys_in.clone(),
                                usb_out: keys_out.clone(),
                                usb_undef: keys_undef.clone(),
                                yubikeys: yubi,
                            };
                            let serialized = serde_json::to_string(&keys)?;
                            match websocket.send(Message::Text(serialized.into())) {
                                Ok(_) => log::debug!("Data wrote into the websocket"),
                                Err(e) => {
                                    log::error!("Cannot write data into the websocket: {e}")
                                }
                            }
                            move_device_out(Path::new(&device))?;
                            info!("Signed USB device done.");
                            ready_out()?;
                        }
                    }
                } else if event.action() == Some(OsStr::new("remove")) {
                    let product = match get_attr_udev(event) {
                        Ok(product) => product,
                        Err(_) => String::from("unknown"),
                    };

                    if product.contains("unknown") {
                        keys_in.clear();
                        keys_out.clear();
                    } else {
                        keys_out.retain(|x| *x != product);
                        keys_in.retain(|x| *x != product);
                        keys_undef.retain(|x| *x != product);
                    }
                    let yubi: Yubistruct = Yubistruct {
                        active: yubikey,
                        yubikeys: list_yubikey(),
                    };
                    let keys: Usbkeys = Usbkeys {
                        usb_in: keys_in.clone(),
                        usb_out: keys_out.clone(),
                        usb_undef: keys_undef.clone(),
                        yubikeys: yubi,
                    };

                    let serialized = serde_json::to_string(&keys)?;
                    websocket.send(Message::Text(serialized.into()))?;
                }

                sthread::sleep(Duration::from_millis(60));
            }
        });
    }
    Ok(())
}

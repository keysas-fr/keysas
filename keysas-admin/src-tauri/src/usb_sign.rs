// SPDX-License-Identifier: GPL-3.0-only
/*
 * The "keysas-sign".
 *
 * (C) Copyright 2019-2023 Stephane Neveu
 *
 * The code for keysas-sign binary.
 */

use crate::get_pki_dir;
use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::SigningKey;
use keysas_lib::keysas_key::KeysasKey;
use keysas_lib::keysas_key::KeysasPQKey;
use libc::{c_int, c_short, c_ulong, c_void};
use std::ffi::OsStr;
use std::fs::File;
use std::io::prelude::*;
use std::io::SeekFrom;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::ptr;
use std::str;
use std::thread;
use std::time::Duration;

#[repr(C)]
#[cfg(target_os = "linux")]
struct pollfd {
    fd: c_int,
    events: c_short,
    revents: c_short,
}

#[repr(C)]
#[cfg(target_os = "linux")]
struct sigset_t {
    __private: c_void,
}

#[allow(non_camel_case_types)]
#[cfg(target_os = "linux")]
type nfds_t = c_ulong;
#[cfg(target_os = "linux")]
const POLLIN: c_short = 0x0001;

#[cfg(target_os = "linux")]
extern "C" {
    fn ppoll(
        fds: *mut pollfd,
        nfds: nfds_t,
        timeout_ts: *mut libc::timespec,
        sigmask: *const sigset_t,
    ) -> c_int;
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
const USB_CA_SUB_DIR: &str = "/CA/usb";

// Remove the partition number and return the device
// TODO: manage if nb partition >= 10
fn rm_last(value: &str) -> &str {
    let chars = value.chars();
    let mut tmp = chars.clone();
    match chars.last() {
        Some(last) => {
            if last.is_numeric() {
                tmp.next_back();
                return tmp.as_str();
            } else {
                return tmp.as_str();
            }
        }
        None => value,
    }
}

/// Construct an hybrid signature from firmware information
#[cfg(target_os = "linux")]
fn sign_device(
    vendor: &str,
    model: &str,
    revision: &str,
    serial: &str,
    direction: &str,
    path_cl: &Path,
    path_pq: &Path,
    password: &str,
) -> Result<String> {
    //use nom::AsBytes;
    let data = format!("{}/{}/{}/{}/{}", vendor, model, revision, serial, direction);
    // Test the private keys by loading them
    let classic_struct = SigningKey::load_keys(path_cl, password)?;
    let pq_pub_struct = KeysasPQKey::load_keys(path_pq, password)?;
    let classic_sig = classic_struct.message_sign(data.as_bytes())?;
    let pq_sig = pq_pub_struct.message_sign(data.as_bytes())?;
    let hybrid_sig = format!(
        "{}|{}",
        general_purpose::STANDARD.encode(classic_sig.as_slice()),
        general_purpose::STANDARD.encode(pq_sig.as_slice())
    );
    log::debug!("{}", hybrid_sig);
    Ok(hybrid_sig)
}

#[cfg(target_os = "linux")]
pub fn watch_new_usb() -> Result<(String, String, String, String, String)> {
    let socket = udev::MonitorBuilder::new()?
        //.match_subsystem_devtype("usb", "usb_device")?
        .match_subsystem("block")?
        .listen()?;

    let mut fds = vec![pollfd {
        fd: socket.as_raw_fd(),
        events: POLLIN,
        revents: 0,
    }];
    log::debug!("Watching... you can plug your device in !");

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
            println!("Error: result is < 0.");
        }

        let event = match socket.iter().next() {
            Some(evt) => evt,
            None => {
                thread::sleep(Duration::from_millis(5));
                continue;
            }
        };

        for _property in event.properties() {
            if event.action() == Some(OsStr::new("add"))
                && event.property_value(
                    OsStr::new("DEVTYPE")
                        .to_str()
                        .ok_or_else(|| anyhow!("Cannot convert DEVTYPE to str."))?,
                ) == Some(OsStr::new("partition"))
            {
                let dev = event.device();
                let device = dev.devnode().unwrap();
                let dev = &device.to_string_lossy();
                let device = rm_last(dev);

                let vendor = event
                    .property_value(
                        OsStr::new("ID_VENDOR_ID")
                            .to_str()
                            .ok_or_else(|| anyhow!("Cannot convert ID_VENDOR_ID to str."))?,
                    )
                    .ok_or_else(|| anyhow!("Cannot get ID_VENDOR_ID from event."))?;
                let model = event
                    .property_value(
                        OsStr::new("ID_MODEL_ID")
                            .to_str()
                            .ok_or_else(|| anyhow!("Cannot convert ID_MODEL_ID to str."))?,
                    )
                    .ok_or_else(|| anyhow!("Cannot get ID_MODEL_ID from event."))?;
                let revision = event
                    .property_value(
                        OsStr::new("ID_REVISION")
                            .to_str()
                            .ok_or_else(|| anyhow!("Cannot convert ID_REVISION to str."))?,
                    )
                    .ok_or_else(|| anyhow!("Cannot get ID_REVISION from event."))?;
                let serial = event
                    .property_value(
                        OsStr::new("ID_SERIAL")
                            .to_str()
                            .ok_or_else(|| anyhow!("Cannot convert ID_SERIAL to str."))?,
                    )
                    .ok_or_else(|| anyhow!("Cannot get ID_SERIAL from event."))?;
                log::debug!(
                    "Found new USB device : Device: {}, Vendor: {}, Model: {}, Revision: {}, Serial: {}",
                    device,
                    vendor.to_string_lossy(),
                    model.to_string_lossy(),
                    revision.to_string_lossy(),
                    serial.to_string_lossy()
                );
                //let information = format!("New USB device found: Vendor ID: {}, Model ID: {}, Revision: {}, Serial number: {}", vendor.to_string_lossy() ,model.to_string_lossy(), revision.to_string_lossy(), serial.to_string_lossy());
                return Ok((
                    device.to_string(),
                    vendor.to_string_lossy().to_string(),
                    model.to_string_lossy().to_string(),
                    revision.to_string_lossy().to_string(),
                    serial.to_string_lossy().to_string(),
                ));
            }
        }
    }
}

pub fn sign_usb(
    device: &str,
    vendor: &str,
    model: &str,
    revision: &str,
    serial: &str,
    direction: &str,
    password: &str,
) -> Result<()> {
    log::debug!("Resetting the MBR for {device}.");
    let mut f = File::options()
        .write(true)
        .read(true)
        .open(device)
        .context("Cannot open device for signing.")?;

    let ss = 512;
    let mut mbr = mbrman::MBR::new_from(&mut f, ss as u32, [0x00, 0x0A, 0x0B, 0x0C])
        .context("Could not make a partition table")?;
    let sectors = mbr
        .get_maximum_partition_size()
        .context("No more space available in the USB device")?;

    let starting_lba = 8192;

    mbr[1] = mbrman::MBRPartitionEntry {
        boot: mbrman::BOOT_INACTIVE,     // boot flag
        first_chs: mbrman::CHS::empty(), // first CHS address (only useful for old computers)
        sys: 0x0c,                       // fat32+ LBA filesystem
        last_chs: mbrman::CHS::empty(),  // last CHS address (only useful for old computers)
        starting_lba,                    // the sector where the partition starts
        sectors,                         // the number of sectors in that partition
    };

    // actually writes the new partition Entry:
    mbr.write_into(&mut f)
        .context("Could not write MBR to disk")?;

    //Let's write behind the magic number now
    let offset = 512;
    // Get path to PKI directory
    let pki_dir = match get_pki_dir() {
        Ok(dir) => dir,
        Err(e) => {
            log::error!("Failed to get PKI directory: {e}");
            return Err(anyhow!("Invalid PKI configuration"));
        }
    };
    let binding_cl = pki_dir.clone() + USB_CA_SUB_DIR + "/usb-cl.p8";
    let path_cl = Path::new(&binding_cl);
    let binding_pq = pki_dir.clone() + USB_CA_SUB_DIR + "/usb-pq.p8";
    let path_pq = Path::new(&binding_pq);

    let attrs = sign_device(
        vendor, model, revision, serial, direction, path_cl, path_pq, password,
    )?;
    let size_u32 = attrs.len() as u32;
    log::info!("Signature size is {}", size_u32);
    f.seek(SeekFrom::Start(offset))?;
    f.write_all(&size_u32.to_be_bytes())?;
    f.write_all(attrs.as_bytes())?;
    log::info!("USB device is now signed successfully.");
    Ok(())
}

pub fn revoke_device(device: &str) -> Result<()> {
    log::debug!("Revoking the device.");
    let mut f = File::options()
        .write(true)
        .read(true)
        .open(device)
        .context("Cannot open device for revoking.")?;

    //Let's write behind the magic number now
    let offset = 512;
    let blank: String = String::from("000000000000000000");
    let size_u32 = blank.len() as u32;
    f.seek(SeekFrom::Start(offset))?;
    f.write_all(&size_u32.to_be_bytes())?;
    f.write_all(blank.as_bytes())?;
    log::info!("USB device is now revoked successfully.");
    Ok(())
}

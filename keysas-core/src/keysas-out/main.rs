// SPDX-License-Identifier: GPL-3.0-only
/*
 * The "keysas-out".
 *
 * (C) Copyright 2019-2025 Stephane Neveu, Luc Bonnafoux
 *
 * This file contains various funtions
 * for building the keysas-out binary.
 */

//! Output daemon
//!
//! Output the files from the processing pipeline into the temporary storage.
//! The daemon also generates a report for the file that contains the result from the checks.
//!
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
//! The report is signed by the station.

#![feature(unix_socket_ancillary_data)]
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
#![warn(missing_docs)]
#![feature(str_split_remainder)]

use anyhow::Result;
use clap::{Arg, ArgAction, Command, crate_version};
use keysas_lib::append_ext;
use keysas_lib::file_report::FileMetadata;
use keysas_lib::file_report::bind_and_sign;
use keysas_lib::file_report::generate_report_metadata;
use keysas_lib::init_logger;
use keysas_lib::keysas_hybrid_keypair::HybridKeyPair;
use keysas_lib::sha256_digest;
use log::{error, info, warn};
use nix::unistd;
use pkcs8::der::EncodePem;
use std::fs::File;
use std::io;
use std::io::BufReader;
use std::io::{BufWriter, IoSliceMut, Write};
use std::os::fd::FromRawFd;
use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{AncillaryData, Messages, SocketAddr, SocketAncillary, UnixStream};
use std::path::Path;
use std::path::PathBuf;
use std::process;
use std::str;
mod sandbox;

/// Structure representing a file and its metadata in the daemon
#[derive(Debug)]
pub struct FileData {
    /// File descriptor
    fd: i32,
    /// Associated file metadata
    md: FileMetadata,
}

/// Directory containing the station signing keys
const KEY_FILE_DIR: &str = "/etc/keysas";
/// Password for the private signing keys PKCS#8 files
/// TODO: Remove this hardcoded pass and add a config file
const KEY_PASSWD: &str = "Keysas007";
/// Directory containing the station configuration
const CONFIG_DIRECTORY: &str = "/etc/keysas";

/// Daemon configuration arguments
struct Configuration {
    /// Path to the socket with keysas-transit
    socket_out: String,
    /// Path to the output directory
    sas_out: String,
    /// True if the file are allowed to pass even if yara failed
    yara_clean: bool,
}

/// This function parse the command arguments into a structure
fn parse_args() -> Configuration {
    let matches = Command::new("keysas-out")
        .version(crate_version!())
        .author("Stephane N.")
        .about("keysas-out, perform file and report write back.")
        .arg(
            Arg::new("socket_out")
                .short('o')
                .long("socket_out")
                .value_name("<NAMESPACE>")
                .default_value("socket_out")
                .action(ArgAction::Set)
                .help("Sets a custom abstract socket for files coming from transit"),
        )
        .arg(
            Arg::new("sas_out")
                .short('g')
                .long("sas_out")
                .value_name("<PATH>")
                .default_value("/var/local/out")
                .action(ArgAction::Set)
                .help("Sets the out sas path for transfering files"),
        )
        .arg(
            Arg::new("yara_clean")
                .short('c')
                .long("yara_clean")
                .action(ArgAction::SetTrue)
                .help("Remove the file if a Yara rule matched"),
        )
        .arg(
            Arg::new("version")
                .short('v')
                .long("version")
                .action(ArgAction::Version)
                .help("Print the version and exit"),
        )
        .get_matches();

    // Unwrap should not panic with default values
    Configuration {
        socket_out: matches.get_one::<String>("socket_out").unwrap().to_string(),
        sas_out: matches.get_one::<String>("sas_out").unwrap().to_string(),
        yara_clean: matches.get_flag("yara_clean"),
    }
}

/// This function retrieves the file descriptors and metadata from the messages
/// messages contains the file descriptor
/// buffer contains the associated file metadata
fn parse_messages(messages: Messages, buffer: &[u8]) -> Vec<FileData> {
    messages
        .filter_map(|m| m.ok())
        .filter_map(|ad| {
            // Filter AncillaryData to keep only ScmRights
            match ad {
                AncillaryData::ScmRights(scm_rights) => Some(scm_rights),
                AncillaryData::ScmCredentials(_) => None,
            }
        })
        .flatten()
        .filter_map(|fd| {
            // Deserialize metadata into a [FileMetadata] struct
            match bincode::deserialize_from::<&[u8], FileMetadata>(buffer) {
                Ok(meta) => Some(FileData { fd, md: meta }),
                Err(e) => {
                    warn!(
                        "Failed to deserialize message from keysas-transit: {e}, killing myself."
                    );
                    process::exit(1);
                }
            }
        })
        .collect()
}

/// This function output files and report received from transit
/// The function first check the digest of the file received
fn output_files(
    files: Vec<FileData>,
    conf: &Configuration,
    sign_keys: Option<&HybridKeyPair>,
    sign_cert: &str,
) -> Result<()> {
    for mut f in files {
        let file = unsafe { File::from_raw_fd(f.fd) };
        // Position the cursor at the beginning of the file
        unistd::lseek(f.fd, 0, unistd::Whence::SeekSet)?;
        // Check digest
        let digest = sha256_digest(&file)?;

        // Test if digest is correct
        if digest.ne(&f.md.digest) {
            warn!("Digest invalid for file {}", f.md.filename);
            f.md.is_digest_ok = false;
        }

        // Generate a report
        let report_meta = generate_report_metadata(&f.md);

        // Bind the report to the file and sign it
        let new_report = bind_and_sign(&f.md, &report_meta, sign_keys, sign_cert)?;

        // Write the report to disk
        let mut path = PathBuf::new();
        path.push(conf.sas_out.clone());
        path.push(&f.md.filename);
        let path = append_ext("krp", path);
        let mut report = File::options()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)?;
        let json_report = serde_json::to_string_pretty(&new_report)?;

        info!("{json_report}");
        writeln!(report, "{json_report}")?;

        // Test if the check passed, if yes write the file to sas_out
        if f.md.is_digest_ok
            && !f.md.is_toobig
            && f.md.is_type_allowed
            && f.md.av_pass
            && !f.md.is_corrupted
            && (f.md.yara_pass || conf.yara_clean)
        {
            // Output file
            let mut reader = BufReader::new(&file);

            let mut path = PathBuf::new();
            path.push(&conf.sas_out);
            path.push(&f.md.filename);

            let output = File::options()
                .write(true)
                .create(true)
                .truncate(true)
                .open(path)?;
            // Position the cursor at the beginning of the file
            unistd::lseek(f.fd, 0, unistd::Whence::SeekSet)?;
            let mut writer = BufWriter::new(output);
            io::copy(&mut reader, &mut writer)?;
        }
        // Release the file in this daemon
        drop(file);
    }

    Ok(())
}

/// Main loop of the daemon
/// It starts by configuring the security (landlock and seccomp), it recovers the
/// station signing keys
/// Then it enters an infinite loops that:
/// 1. Get file descriptors and metadata from transit
/// 2. Parse them
/// 3. Create reports for each file and outputs them with the file to the output directory
fn main() -> Result<()> {
    // Parse command arguments
    let config = parse_args();

    // Configure logger
    init_logger();

    //Init Landlock
    match sandbox::landlock_sandbox(&config.sas_out) {
        Ok(_) => log::info!("Landlock sandbox activated."),
        Err(e) => log::warn!("Landlock sandbox cannot be activated: {e}"),
    }
    // Init Seccomp filters
    match sandbox::init() {
        Ok(_) => log::info!("Seccomp sandbox activated."),
        Err(e) => log::warn!("Seccomp sandbox cannot be activated: {e}"),
    }

    // Load station signing keys and certificate
    let sign_keys = match HybridKeyPair::load(
        "file-sign",
        Path::new(KEY_FILE_DIR),
        Path::new(KEY_FILE_DIR),
        Path::new("."),
        KEY_PASSWD,
    ) {
        Ok(k) => Some(k),
        Err(e) => {
            warn!("Failed to load station signing keys {e}");
            None
        }
    };

    // Convert certificates to PEM string so that it can be placed in the reports
    let mut sign_cert = String::new();
    if let Some(ref keys) = sign_keys {
        let pem_cl = match keys.classic_cert.to_pem(pkcs8::LineEnding::LF) {
            Ok(p) => p,
            Err(e) => {
                error!("Failed to convert certificate to string {e}");
                process::exit(1);
            }
        };
        sign_cert.push_str(&pem_cl);
        // Add a delimiter between the two certificates
        sign_cert.push('|');
        let pem_pq = match keys.pq_cert.to_pem(pkcs8::LineEnding::LF) {
            Ok(p) => p,
            Err(e) => {
                error!("Failed to convert certificate to string {e}");
                process::exit(1);
            }
        };
        sign_cert.push_str(&pem_pq);
    }

    // Open socket with keysas-transit
    let addr_out = SocketAddr::from_abstract_name(&config.socket_out)?;
    let sock_out = match UnixStream::connect_addr(&addr_out) {
        Ok(s) => {
            info!("Connected to keysas-transit socket.");
            s
        }
        Err(e) => {
            error!("Failed to open abstract socket with keysas-transit {e}");
            process::exit(1);
        }
    };

    // Allocate buffers for input messages
    let mut ancillary_buffer_in = [0; 128];
    let mut ancillary_in = SocketAncillary::new(&mut ancillary_buffer_in[..]);

    // Main loop
    // 1. receive file descriptor and metadata from transit
    // 2. Write file and report to output
    loop {
        // 4128 => filename max 4096 bytes and digest 32 bytes
        let mut buf_in = [0; 4128];
        let bufs_in = &mut [IoSliceMut::new(&mut buf_in[..])][..];

        // Listen for message on socket
        match sock_out.recv_vectored_with_ancillary(bufs_in, &mut ancillary_in) {
            Ok(_) => (),
            Err(e) => {
                warn!("Failed to receive fds from in: {e}");
                process::exit(1);
            }
        }

        // Parse messages received
        let files = parse_messages(ancillary_in.messages(), &buf_in);

        // Output file
        output_files(files, &config, sign_keys.as_ref(), &sign_cert)?;
    }
}

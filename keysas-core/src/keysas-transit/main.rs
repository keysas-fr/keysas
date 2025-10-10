// SPDX-License-Identifier: GPL-3.0-only
/*
 * The "keysas-out".
 *
 * (C) Copyright 2019-2025 Stephane Neveu, Luc Bonnafoux
 *
 * This file contains various funtions
 * for building the keysas-out binary.
 */

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

use anyhow::Result;
use bincode::Options;
use clamav_tcp::scan;
use clamav_tcp::version;
use clap::{Arg, ArgAction, Command, crate_version};
use infer::get;
use keysas_lib::init_logger;
use keysas_lib::sha256_digest;
use log::{error, info, warn};
use nix::unistd;
use std::fs::File;
use std::io::{BufReader, Read};
use std::io::{IoSlice, IoSliceMut};
use std::net::IpAddr;
use std::net::ToSocketAddrs;
use std::os::fd::FromRawFd;
use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{
    AncillaryData, Messages, SocketAddr, SocketAncillary, UnixListener, UnixStream,
};
use std::process;
use std::str;
use std::thread as main_thread;
use std::time::Duration;
use yara::*;
mod sandbox;

const CONFIG_DIRECTORY: &str = "/etc/keysas";

#[macro_use]
extern crate serde_derive;
use serde_derive::Deserialize;

#[derive(Deserialize, Debug)]
struct InputMetadata {
    filename: String,
    digest: String,
    timestamp: String,
    is_corrupted: bool,
}

#[derive(Serialize, Debug)]
struct FileMetadata {
    filename: String,
    digest: String,
    is_digest_ok: bool,
    is_toobig: bool,
    size: u64,
    is_type_allowed: bool,
    av_pass: bool,
    av_report: Vec<String>,
    yara_pass: bool,
    yara_report: String,
    timestamp: String,
    is_corrupted: bool,
    file_type: String,
}

#[derive(Debug)]
struct FileData {
    fd: i32,
    md: FileMetadata,
}

/// Daemon configuration arguments
struct Configuration {
    socket_in: String,         // path for the socket with keysas-in
    socket_out: String,        // path for the socket with keysas-out
    max_size: u64,             // Maximum size for files
    magic_list: Vec<String>,   // List of allowed file type
    clamav_ip: String,         // ClamAV IP address
    clamav_port: u16,          // ClamAV port number
    rule_path: String,         // Path to yara rules
    yara_timeout: i32,         // Timeout for yara
    yara_rules: Option<Rules>, // Yara rules
    type_off: bool,
}

/// This function parse the command arguments into a structure
fn parse_args() -> Configuration {
    let matches = Command::new("keysas-transit")
          .version(crate_version!())
          .author("Stephane N.")
          .about("keysas-transit, perform file sanitization.")
          .arg(
             Arg::new("socket_in")
                 .short('i')
                 .long("socket_in")
                 .value_name("<NAMESPACE>")
                 .default_value("socket_in")
                 .action(ArgAction::Set)
                 .help("Sets a custom abstract socket for input files"),
         )
         .arg(
             Arg::new("socket_out")
                 .short('o')
                 .long("socket_out")
                 .value_name("<NAMESPACE>")
                 .default_value("socket_out")
                 .action(ArgAction::Set)
                 .help("Sets a custom abstract socket for output files"),
         )
         .arg(
             Arg::new("max_size")
                 .short('s')
                 .long("max_size")
                 .value_name("<SIZE_IN_BYTES>")
                 .default_value("500000000")
                 .action(ArgAction::Set)
                 .value_parser(clap::value_parser!(u64))
                 .help("Maximum size for files"),
         )
         .arg(
             Arg::new("allowed_formats")
                 .short('a')
                 .long("allowed_formats")
                 .value_name("<LIST>")
                 .default_value("jpg,png,gif,bmp,mp4,m4v,avi,wmv,mpg,flv,mp3,wav,ogg,epub,mobi,doc,docx,xls,xlsx,ppt,pptx")
                 .action(ArgAction::Set)
                 .help("Whitelist (comma separated) of allowed file formats"),
         )
         .arg(
             Arg::new("clamavip")
                 .short('c')
                 .long("clamavip")
                 .value_name("<IP>")
                 .default_value("127.0.0.1")
                 .action(ArgAction::Set)
                 .help("Clamav IP address"),
         )
         .arg(
             Arg::new("clamavport")
                 .short('p')
                 .long("clamavport")
                 .value_name("<PORT>")
                 .default_value("3310")
                 .action(ArgAction::Set)
                 .value_parser(clap::value_parser!(u16))
                 .help("Clamav port number"),
         )
         .arg(
             Arg::new("rules_path")
                 .short('r')
                 .long("rules_path")
                 .value_name("<PATH>")
                 .default_value("/usr/share/keysas/rules/index.yar")
                 .action(ArgAction::Set)
                 .help("Sets a custom path for Yara rules"),
         )
         .arg(
             Arg::new("yara_timeout")
                 .short('t')
                 .long("yara_timeout")
                 .value_name("<SECONDS>")
                 .default_value("100")
                 .action(ArgAction::Set)
                 .value_parser(clap::value_parser!(i32))
                 .help("Sets a custom timeout for libyara scans"),
         )
         .arg(
            Arg::new("type_off")
                .short('m')
                .long("type_off")
                .action(ArgAction::SetTrue)
                .help("Disable the magic number check"),
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
        socket_in: matches.get_one::<String>("socket_in").unwrap().to_string(),
        socket_out: matches.get_one::<String>("socket_out").unwrap().to_string(),
        max_size: *matches.get_one::<u64>("max_size").unwrap(),
        magic_list: matches
            .get_one::<String>("allowed_formats")
            .unwrap()
            .split(',')
            .map(String::from)
            .collect(),
        clamav_ip: matches.get_one::<String>("clamavip").unwrap().to_string(),
        clamav_port: *matches.get_one::<u16>("clamavport").unwrap(),
        rule_path: matches.get_one::<String>("rules_path").unwrap().to_string(),
        yara_timeout: *matches.get_one::<i32>("yara_timeout").unwrap(),
        yara_rules: None,
        type_off: matches.get_flag("type_off"),
    }
}

/// This function retrieves the file descriptors and metadata from the messages
fn parse_messages(messages: Messages, buffer: &[u8]) -> Vec<FileData> {
    messages
        .filter_map(|m| {
            //Desencapsulate Result
            match m {
                Ok(ad) => Some(ad),
                Err(e) => {
                    log::warn!("failed to get ancillary data: {e:?}");
                    None
                }
            }
        })
        .filter_map(|ad| {
            // Filter AncillaryData to keep only ScmRights
            match ad {
                AncillaryData::ScmRights(scm_rights) => Some(scm_rights),
                AncillaryData::ScmCredentials(_) => None,
            }
        })
        .flatten()
        .filter_map(|fd| {
            // Deserialize metadata
            let _my_options = bincode::DefaultOptions::new().with_limit(4128);
            match bincode::deserialize_from::<&[u8], InputMetadata>(buffer) {
                Ok(meta) => {
                    // Initialize with failed value by default
                    log::info!("Receiving fd of file: {}", &meta.filename);
                    Some(FileData {
                        fd,
                        md: FileMetadata {
                            filename: meta.filename,
                            digest: meta.digest,
                            is_digest_ok: false,
                            is_toobig: true,
                            size: 0,
                            is_type_allowed: false,
                            av_pass: false,
                            av_report: Vec::new(),
                            yara_pass: false,
                            yara_report: String::new(),
                            timestamp: meta.timestamp,
                            is_corrupted: meta.is_corrupted,
                            file_type: "Unknown".into(),
                        },
                    })
                }
                Err(e) => {
                    log::warn!("Failed to deserialize message from in: {e}");
                    None
                }
            }
        })
        .collect()
}

/// This function returns true if the file type is in the list provided
fn check_is_extension_allowed(buf: &[u8], conf: &Configuration) -> bool {
    match get(buf) {
        Some(info) => conf.magic_list.contains(&info.extension().to_string()),
        None => false,
    }
}
/// This function returns true if the file type is in the list provided
fn get_extension(buf: Vec<u8>) -> String {
    match get(&buf) {
        Some(info) => info.to_string(),
        None => "".into(),
    }
}
/// This function check each file given in the input vector.
/// Checks are made against the provided configuration.
/// Checks performed are:
///     - File digest is correct
///     - File size is less than maximum size provided in configuration
///     - File type is in the list provided in configuration
///     - Anti-virus check
///     - Yara rules check
/// Checks results are marked in file metadata.
/// This function does not modify the files.
fn check_files(files: &mut Vec<FileData>, conf: &Configuration, clam_addr: String) {
    for f in files {
        match unistd::dup2(f.fd, 500) {
            Ok(nfd) => {
                // Safety: We are using a file descriptor that we know is valid
                let mut file = unsafe { File::from_raw_fd(nfd) };
                // Synchronize the file before calculating the SHA256 hash
                match file.sync_all() {
                    Ok(_) => (),
                    Err(e) => {
                        error!("Failed to synchronize file: {e}");
                    }
                }
                // Position the cursor at the beginning of the file
                match unistd::lseek(nfd, 0, unistd::Whence::SeekSet) {
                    Ok(_) => (),
                    Err(e) => {
                        error!("Unable to lseek on file descriptor: {e:?}, killing myself.");
                        process::exit(1);
                    }
                }
                // Check digest
                match sha256_digest(&file) {
                    Ok(d) => {
                        f.md.is_digest_ok = f.md.digest.eq(&d);
                    }
                    Err(e) => {
                        warn!(
                            "Failed to calculate digest for file {}, error {e}.",
                            f.md.filename
                        );
                    }
                }
                // Position the cursor at the beginning of the file
                match unistd::lseek(nfd, 0, unistd::Whence::SeekSet) {
                    Ok(_) => (),
                    Err(e) => {
                        error!("Unable to lseek on file descriptor: {e:?}, killing myself.");
                        process::exit(1);
                    }
                }

                // Check size
                match &file.metadata() {
                    Ok(meta) => {
                        f.md.is_toobig = meta.len().gt(&conf.max_size);
                        f.md.size = meta.len();
                    }
                    Err(e) => {
                        warn!("Failed to get metadata of file {} error {e}", f.md.filename);
                    }
                }

                // Position the cursor at the beginning of the file
                match unistd::lseek(nfd, 0, unistd::Whence::SeekSet) {
                    Ok(_) => (),
                    Err(e) => {
                        error!("Unable to lseek on file descriptor: {e:?}, killing myself.");
                        process::exit(1);
                    }
                }
                // Check anti-virus
                match scan(clam_addr.clone(), &mut file, None) {
                    Ok(result) => {
                        f.md.av_pass = !result.is_infected;
                        f.md.av_report = result.detected_infections;
                    }
                    Err(e) => {
                        error!("Failed to run clam on file {e}");
                        f.md.av_pass = false;
                    }
                }

                // Position the cursor at the beginning of the file
                match unistd::lseek(nfd, 0, unistd::Whence::SeekSet) {
                    Ok(_) => (),
                    Err(e) => {
                        error!("Unable to lseek on file descriptor: {e:?}, killing myself.");
                        process::exit(1);
                    }
                }
                // Check yara rules
                match &conf.yara_rules {
                    Some(rules) => match rules.scan_fd(&file, conf.yara_timeout) {
                        Ok(results) => match results.is_empty() {
                            true => {
                                f.md.yara_pass = true;
                            }
                            false => {
                                for result in results {
                                    f.md.yara_report.push_str(result.identifier);
                                }
                                f.md.yara_pass = false;
                                warn!("Yara rules matched");
                            }
                        },
                        Err(e) => {
                            error!("Yara cannot scan file {} error {e}", f.md.filename);
                        }
                    },
                    None => {
                        error!("Yara rules not present");
                        f.md.yara_pass = false;
                    }
                }
                // Position the cursor at the beginning of the file
                match unistd::lseek(nfd, 0, unistd::Whence::SeekSet) {
                    Ok(_) => (),
                    Err(e) => {
                        error!("Unable to lseek on file descriptor: {e:?}, killing myself.");
                        process::exit(1);
                    }
                }
                // Check the magic number
                // Read only 1Mo of the file to be faster and do not read large files
                let reader = BufReader::new(&file);
                let limited_reader = &mut reader.take(1024 * 1024);
                let mut buffer = Vec::new();
                match limited_reader.read_to_end(&mut buffer) {
                    Ok(_) => {
                        if !conf.type_off {
                            f.md.is_type_allowed = check_is_extension_allowed(&buffer, conf);
                            f.md.file_type = get_extension(buffer);
                        } else {
                            f.md.is_type_allowed = true;
                            f.md.file_type = get_extension(buffer);
                        }
                    }
                    Err(e) => {
                        error!(
                            "Cannot read limited buffer: {e:?}, file will be marked as not allowed !"
                        );
                        f.md.is_type_allowed = false;
                        f.md.file_type = "Unknown".into();
                    }
                }
            }
            Err(e) => {
                error!("Cannot duplicate file descriptor for analysing: {e:?}, killing myself.");
                process::exit(1);
            }
        };
        log::info!(
            "Report for {}: digest_ok: {}, type_allowed: {}, yara_pass: {}, av_pass: {}, too_big: {}",
            f.md.filename,
            f.md.is_digest_ok,
            f.md.is_type_allowed,
            f.md.yara_pass,
            f.md.av_pass,
            f.md.is_toobig
        );
    }
}

/// This functions send the files filedescriptor and metadata to the socket
fn send_files(files: &Vec<FileData>, stream: &UnixStream) {
    for file in files {
        // Get metadata
        let data = match bincode::serialize(&file.md) {
            Ok(d) => d,
            Err(e) => {
                error!("Failed to serialize: {e}");
                process::exit(1);
            }
        };
        let bufs = &[IoSlice::new(&data[..])];

        // Send them on the socket
        let mut ancillary_buffer = [0; 4096];
        let mut ancillary = SocketAncillary::new(&mut ancillary_buffer);
        ancillary.add_fds(&[file.fd][..]);
        match stream.send_vectored_with_ancillary(&bufs[..], &mut ancillary) {
            Ok(_) => info!("File {} sent to Keysas-out.", file.md.filename),
            Err(e) => error!("Failed to send file {e}."),
        }
        // Close the file descriptor
        match unistd::close(file.fd) {
            Ok(_) => info!("File descriptor {} closed for file {}.", file.fd, file.md.filename),
            Err(e) => error!("Failed to close file descriptor {} for file {}: {e}", file.fd, file.md.filename),
        }
    }
}

fn main() -> Result<()> {
    // Parse command arguments
    let mut config = parse_args();

    // Configure logger
    init_logger();

    // Landlock initialization
    match sandbox::landlock_sandbox(&config.rule_path) {
        Ok(_) => log::info!("Landlock sandbox activated."),
        Err(e) => log::warn!("Landlock sandbox cannot be activated: {e}"),
    }
    // Seccomp initialization
    match sandbox::init() {
        Ok(_) => log::info!("Seccomp sandbox activated."),
        Err(e) => log::warn!("Seccomp sandbox cannot be activated: {e}"),
    }
    // Initilize clamd client
    // Test if ClamAV IP is valid
    match config.clamav_ip.parse::<IpAddr>() {
        Ok(_) => (),
        Err(e) => {
            error!("ClamAV invalid IP address {e}");
            process::exit(1);
        }
    }
    // Test if clamd is responding
    let url = format!("{}{}{}", &config.clamav_ip, ":", config.clamav_port);
    match url.to_socket_addrs() {
        Ok(mut socket_addrs) => match socket_addrs.next() {
            Some(clam_addr) => match version(clam_addr) {
                Ok(v) => info!("Version: {v}"),
                Err(e) => {
                    error!("Clamav not available: {e:?}, killing my self.");
                    process::exit(1);
                }
            },
            None => {
                error!(
                    "Cannot parse any valid SocketAddr for connecting to clamav server, killing my self."
                );
                process::exit(1);
            }
        },
        Err(e) => {
            error!("Cannot parse clamav configuration: {e:?}")
        }
    };

    // Initialize yara rules
    match Compiler::new() {
        Ok(c) => match c.add_rules_file_with_namespace(&config.rule_path, "keysas") {
            Ok(c) => match c.compile_rules() {
                Ok(r) => {
                    info!("Yara compiler initialized.");
                    config.yara_rules = Some(r);
                }
                Err(e) => {
                    error!("Failed to compile yara rules {e}");
                    process::exit(1);
                }
            },
            Err(e) => {
                error!("Failed to add yara rules to compiler {e}");
                process::exit(1);
            }
        },
        Err(e) => {
            error!("Failed to initialize yara compiler {e}");
            process::exit(1);
        }
    };

    // Open socket with keysas-in
    let addr_in = SocketAddr::from_abstract_name(&config.socket_in)?;
    let sock_in = match UnixStream::connect_addr(&addr_in) {
        Ok(s) => {
            info!("Connected to Keysas-in socket.");
            s
        }
        Err(e) => {
            error!("Failed to open socket with keysas-in {e}");
            process::exit(1);
        }
    };

    // Open socket with keysas-out
    let addr_out = SocketAddr::from_abstract_name(&config.socket_out)?;
    let sock_out = match UnixListener::bind_addr(&addr_out) {
        Ok(s) => {
            info!("Socket for Keysas-out created.");
            s
        }
        Err(e) => {
            error!("Failed to open socket with keysas-out {e}");
            process::exit(1);
        }
    };

    // Wait to be connected with keysas-out before starting to accept files in
    let (out_stream, _sck_addr) = match sock_out.accept() {
        Ok(r) => r,
        Err(e) => {
            error!("Failed to accept connection: {e}");
            process::exit(1);
        }
    };

    // Allocate buffers for input messages
    let mut ancillary_buffer_in = [0; 128];
    let mut ancillary_in = SocketAncillary::new(&mut ancillary_buffer_in[..]);

    // Main loop
    // 1. receive file descriptors from in
    // 2. run check on the file
    // 3. send fd and report to out
    loop {
        // 4128 => filename max 4096 bytes and digest 32 bytes
        let mut buf_in = [0; 4128];
        let bufs_in = &mut [IoSliceMut::new(&mut buf_in[..])][..];

        // Listen for message on socket
        match sock_in.recv_vectored_with_ancillary(bufs_in, &mut ancillary_in) {
            Ok(size) => info!("Receiving data from keysas-in, message size: {size}"),
            Err(e) => {
                warn!("Failed to receive fds from in: {e}");
                process::exit(1);
            }
        }

        // Parse messages received
        let mut files = parse_messages(ancillary_in.messages(), &buf_in);

        // Run check on message received
        check_files(&mut files, &config, url.clone());

        // Send fd and report to out
        send_files(&files, &out_stream);
        main_thread::sleep(Duration::from_millis(100));
    }
}

// SPDX-License-Identifier: GPL-3.0-only
/*
 * The "keysas-in".
 *
 * (C) Copyright 2019-2023 Stephane Neveu, Luc Bonnafoux
 *
 * This file contains various funtions
 * for building the keysas-in binary.
 */
#![feature(unix_socket_ancillary_data)]
#![feature(tcp_quickack)]
#![forbid(unsafe_code)]
#![warn(unused_extern_crates)]
#![forbid(non_shorthand_field_patterns)]
#![warn(dead_code)]
#![warn(missing_debug_implementations)]
#![warn(missing_copy_implementations)]
#![warn(trivial_casts)]
#![warn(trivial_numeric_casts)]
#![warn(unused_extern_crates)]
#![warn(unused_import_braces)]
#![warn(unused_qualifications)]
#![warn(variant_size_differences)]
#![forbid(private_in_public)]
#![warn(overflowing_literals)]
#![warn(deprecated)]

use anyhow::{Context, Result};
//use bincode::serialize;
use clap::{crate_version, Arg, ArgAction, Command};
use itertools::MultiUnzip;
use keysas_lib::append_ext;
use landlock::{
    path_beneath_rules, Access, AccessFs, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetError,
    RulesetStatus, ABI,
};
use log::{debug, error, info, warn};
use nix::unistd::unlinkat;
use nix::unistd::UnlinkatFlags;
use regex::Regex;
use std::fs::remove_file;
use std::fs::File;
use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr, SocketAncillary, UnixListener, UnixStream};
use std::path::Path;
use std::path::PathBuf;
use std::process;
use std::thread as main_thread;
use std::time::Duration;
use time::OffsetDateTime;
mod tests;

#[macro_use]
extern crate serde_derive;
use keysas_lib::{convert_ioslice, init_logger, list_files, sha256_digest};

const CONFIG_DIRECTORY: &str = "/etc/keysas";

#[derive(Serialize, Debug, Clone)]
struct FileMetadata {
    filename: String,
    digest: String,
    timestamp: String,
    is_corrupted: bool,
}

struct Config {
    sas_in: String,
    socket_in: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            sas_in: "/var/local/in/".to_string(),
            socket_in: "socket_in".to_string(),
        }
    }
}
fn landlock_sandbox(sas_in: &String) -> Result<(), RulesetError> {
    let abi = ABI::V2;
    let status = Ruleset::new()
        .handle_access(AccessFs::from_all(abi))?
        .create()?
        // Read-only access.
        .add_rules(path_beneath_rules(
            &[CONFIG_DIRECTORY],
            AccessFs::from_read(abi),
        ))?
        // Read-write access.
        .add_rules(path_beneath_rules(&[sas_in], AccessFs::from_all(abi)))?
        .restrict_self()?;
    match status.ruleset {
        // The FullyEnforced case must be tested.
        RulesetStatus::FullyEnforced => info!("Keysas-in is now fully sandboxed using Landlock !"),
        RulesetStatus::PartiallyEnforced => {
            warn!("Keysas-in is only partially sandboxed using Landlock !")
        }
        // Users should be warned that they are not protected.
        RulesetStatus::NotEnforced => {
            warn!("Keysas-in: Not sandboxed with Landlock ! Please update your kernel.")
        }
    }
    Ok(())
}

fn command_args(config: &mut Config) {
    let matches = Command::new("keysas-in")
        .version(crate_version!())
        .author("Stephane N.")
        .about("keysas-in, input SAS.")
        .arg(
            Arg::new("sas_in")
                .short('i')
                .long("sas_in")
                .value_name("Sets path for incoming directory")
                .default_value("/var/local/in/")
                .action(ArgAction::Set)
                .help("Path for incoming SAS"),
        )
        .arg(
            Arg::new("socket_in")
                .short('s')
                .long("socket_in")
                .value_name("<NAMESPACE>")
                .default_value("socket_in")
                .action(ArgAction::Set)
                .help("Namespace for in-transit abstract socket"),
        )
        .arg(
            Arg::new("version")
                .short('v')
                .long("version")
                .action(ArgAction::Version)
                .help("Print the version and exit"),
        )
        .get_matches();

    //Won't panic according to clap authors
    if let Some(p) = matches.get_one::<String>("sas_in") {
        config.sas_in = p.to_string();
    }
    if let Some(p) = matches.get_one::<String>("socket_in") {
        config.socket_in = p.to_string();
    }
}

fn is_corrupted(file: PathBuf) -> bool {
    if file.exists() && file.is_file() {
        match file.extension() {
            Some(ext) => {
                if ext.eq("ioerror") {
                    debug!("Ioerror report detected.");
                    let corrupted_filename = match file.file_stem() {
                        Some(c) => c,
                        None => return false,
                    };
                    let mut path = match file.parent() {
                        Some(p) => p.to_path_buf(),
                        None => PathBuf::new(),
                    };
                    path.push(corrupted_filename);
                    debug!("Corrupted file should be: {:?}", path);
                    path.exists() && path.is_file()
                } else {
                    let ioerror = append_ext("ioerror", file);
                    ioerror.exists() && ioerror.is_file()
                }
            }
            None => {
                let ioerror = append_ext("ioerror", file);
                ioerror.exists() && ioerror.is_file()
            }
        }
    } else {
        true
    }
}

fn send_files(files: &[String], stream: &UnixStream, sas_in: &String) -> Result<()> {
    //Remove any file starting by .(dot)
    let re = Regex::new(r"^\.([a-z])*")?;
    let mut files = files.to_owned();
    files.retain(|x| !re.is_match(x));
    //Don't catch .ioerror reports generated by keysas-io
    let re_ioerror = Regex::new(r"\.ioerror")?;
    files.retain(|x| !re_ioerror.is_match(x));
    //Max X files per send in .chunks(X)
    for batch in files.chunks(1) {
        let (bufs, fhs, fs): (Vec<Vec<u8>>, Vec<File>, Vec<PathBuf>) = batch
            .iter()
            .map(|f| {
                let mut base_path = PathBuf::from(&sas_in);
                base_path.push(f);
                base_path
            })
            .filter_map(|f| {
                // FD is opened in read-write mode
                let fh = match File::open(&f) {
                    Ok(f) => f,
                    Err(e) => {
                        error!("Failed to open file {}: {e}", f.display());
                        process::exit(1);
                    }
                };
                let digest = match sha256_digest(&fh) {
                    Ok(d) => d,
                    Err(e) => {
                        error!("Failed to compute hash {e}");
                        return None;
                    }
                };
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

                let m = FileMetadata {
                    filename: f.file_name()?.to_str()?.to_string(),
                    digest,
                    timestamp,
                    is_corrupted: is_corrupted(f.clone()),
                };

                // Remove the report in sas_in
                if m.is_corrupted {
                    let ioerror_report = append_ext("ioerror", f.clone());
                    match remove_file(ioerror_report) {
                        Ok(_) => (),
                        Err(e) => error!("Cannot remove ioerror report: {e}"),
                    }
                }
                let data: Vec<u8> = match bincode::serialize(&m) {
                    Ok(d) => d,
                    Err(_e) => {
                        error!("Failed to serialize FileMetadata");
                        return None;
                    }
                };
                Some((data, fh, f))
            })
            .multiunzip();

        let (ios, fds) = convert_ioslice(&fhs, &bufs);

        let mut ancillary_buffer = [0; 4128];
        let mut ancillary = SocketAncillary::new(&mut ancillary_buffer[..]);
        ancillary.add_fds(&fds[..]);
        match stream.send_vectored_with_ancillary(&ios[..], &mut ancillary) {
            Ok(_) => {
                info!("Chunk of file descriptors has been sent");
            }
            Err(e) => error!("Failed to send fds: {e}"),
        }
        // Files are unlinked once fds are sent
        for it in fs.iter().zip(fds.iter()) {
            let (file_path, fd) = it;
            match unlinkat(Some(*fd), file_path, UnlinkatFlags::NoRemoveDir) {
                Ok(_) => info!("File {:?} has been removed.", file_path),
                Err(e) => error!("Cannot unlink file {:?}: {:?}", file_path, e),
            };
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    // TODO:
    // - Add seccomp whitelist
    // - Check that fd is not dir

    let mut config = Config::default();
    command_args(&mut config);
    init_logger();
    landlock_sandbox(&config.sas_in)?;

    info!("Keysas-in started :)");
    info!("Running configuration is:");
    info!("- Abstract socket: {}", &config.socket_in);
    info!("- sas_in: {}", &config.sas_in);
    if Path::new(&config.socket_in).exists() {
        match remove_file(&config.socket_in) {
            Ok(_) => debug!("Removing previously created socket_in"),
            Err(why) => {
                error!("Cannot remove previously created socket_in: {:?}", why);
                process::exit(1);
            }
        }
    }
    let addr = SocketAddr::from_abstract_name(config.socket_in)?;
    let sock = match UnixListener::bind_addr(&addr) {
        Ok(s) => {
            info!("Socket for Keysas-transit created.");
            s
        }
        Err(e) => {
            error!("Failed to create abstract socket: {e}");
            process::exit(1);
        }
    };
    let (unix_stream, _sck_addr) = match sock.accept() {
        Ok(r) => r,
        Err(e) => {
            error!("Failed to accept connection: {e}");
            process::exit(1);
        }
    };

    loop {
        let files = match list_files(&config.sas_in) {
            Ok(fs) => fs,
            Err(e) => {
                error!("Failed to list files in directory {}: {e}", &config.sas_in);
                process::exit(1);
            }
        };

        send_files(&files, &unix_stream, &config.sas_in)
            .context("Cannot send file descriptors :/")?;
        main_thread::sleep(Duration::from_millis(500));
    }
}

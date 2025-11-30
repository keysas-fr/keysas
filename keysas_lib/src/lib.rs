// SPDX-License-Identifier: GPL-3.0-only
/*
 *
 * (C) Copyright 2019-2025 Stephane Neveu, Luc Bonnafoux
 *
 * This file contains various utility functions
 */

//! This module contains utility functions for the rest of Keysas

#![feature(str_split_remainder)]
use anyhow::Result;
use regex::Regex;
use sha2::{Digest, Sha256};
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::fs::File;
#[cfg(target_os = "linux")]
use std::io::IoSlice;
use std::io::{BufReader, Read};
#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;

pub mod certificate_field;
pub mod file_report;
pub mod keysas_hybrid_keypair;
pub mod keysas_key;
pub mod pki;

// Init logger
pub fn init_logger() {
    if env::var("RUST_LOG").is_ok() {
        simple_logger::init_with_env().unwrap();
    } else {
        simple_logger::init_with_level(log::Level::Info).unwrap();
    }
}

/// This function computes the SHA-256 digest of a file
///
/// Example:
///```
/// use keysas_lib::sha256_digest;
/// use std::path::Path;
/// use tempfile::tempdir;
/// use std::fs::File;
/// use std::fs;
///
/// let dir = tempdir().unwrap();
/// let path = dir.path().join("test");
/// let _output = fs::create_dir_all(&path).unwrap();
/// assert_eq!(true, Path::new(&path).exists());
/// let path = path.join("file.txt");
/// let _file = File::create(&path).unwrap();
/// let fd = File::open(path).unwrap();
/// //assert_eq!(true, Path::new(&fd).exists());
/// let digest = sha256_digest(&fd).unwrap();
/// assert_eq!(digest, String::from("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"))
/// ```
pub fn sha256_digest(input: &File) -> Result<String> {
    let mut reader = BufReader::new(input);

    let digest = {
        let mut hasher = Sha256::new();
        let mut buffer = [0; 1_048_576];
        loop {
            let count = reader.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
        }
        hasher.finalize()
    };
    Ok(format!("{digest:x}"))
}

/// This function lists all files in a directory except hidden ones or links.
///
/// Example:
/// ```
/// use keysas_lib::list_files;
/// use std::path::Path;
/// use tempfile::tempdir;
/// use std::fs::File;
/// use std::fs;
///
/// let dir = tempdir().unwrap();
/// let path = dir.path().join("transit");
/// let _output = fs::create_dir_all(&path).unwrap();
/// assert_eq!(true, Path::new(&path).exists());
/// let file = path.join("file.txt");
/// let _output = File::create(&file).unwrap();
/// assert_eq!(true, Path::new(&file).exists());
/// let files = list_files(path.to_str().unwrap());
/// assert_eq!(files.unwrap(), ["file.txt"]);
/// ```
pub fn list_files(directory: &str) -> Result<Vec<String>> {
    let paths: std::fs::ReadDir = fs::read_dir(directory)?;

    let mut names = paths
        .filter_map(|entry| {
            entry.ok().and_then(|e| {
                let path = e.path();
                if path.is_file() {
                    path.file_name().and_then(|n| n.to_str().map(String::from))
                } else {
                    None
                }
            })
        })
        .collect::<Vec<String>>();
    // Not sending any files starting with dot like .bashrc
    let re = Regex::new(r"^\.([a-z])*")?;
    names.retain(|x| !re.is_match(x));
    Ok(names)
}

#[cfg(target_os = "linux")]
pub fn convert_ioslice<'a>(
    files: &'a Vec<File>,
    input: &'a Vec<Vec<u8>>,
) -> (Vec<IoSlice<'a>>, Vec<i32>) {
    let mut ios: Vec<IoSlice> = Vec::new();
    let mut fds: Vec<i32> = Vec::new();
    for i in input {
        ios.push(IoSlice::new(&i[..]));
    }

    for file in files {
        fds.push(file.as_raw_fd());
    }
    (ios, fds)
}

/// Returns a path with a new dotted extension component appended to the end.
/// Note: does not check if the path is a file or directory; you should do that.
/// # Example
/// ```
/// use keysas_lib::append_ext;
/// use std::path::PathBuf;
/// let path = PathBuf::from("foo/bar/baz.txt");
/// if !path.is_dir() {
///    assert_eq!(append_ext("app", path), PathBuf::from("foo/bar/baz.txt.app"));
/// }
/// ```
///
pub fn append_ext(ext: impl AsRef<OsStr>, path: PathBuf) -> PathBuf {
    let mut os_string: OsString = path.into();
    os_string.push(".");
    os_string.push(ext.as_ref());
    os_string.into()
}

// SPDX-License-Identifier: GPL-3.0-only
/*
 * The "keysas-sign".
 *
 * (C) Copyright 2019-2025 Stephane Neveu
 *
 * The code for keysas-sign binary.
 */

use std::{net::TcpListener, path::Path, thread::spawn};

use anyhow::Result;
use landlock::{
    ABI, Access, AccessFs, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetError, RulesetStatus,
    path_beneath_rules,
};
use nom::IResult;
use nom::bytes::complete::take_until;
use regex::Regex;
use std::fs;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::Duration;
use tungstenite::{
    Message, accept_hdr,
    handshake::server::{Request, Response},
};

extern crate serde;
extern crate serde_json;
#[macro_use]
extern crate serde_derive;

extern crate libc;
extern crate regex;

const SAS_IN: &str = "/var/local/in";
const SAS_OUT: &str = "/var/local/out";
const LOCK_IN: &str = "/var/lock/keysas/keysas-in";
const LOCK_TRANSIT: &str = "/var/lock/keysas/keysas-transit";
const LOCK_OUT: &str = "/var/lock/keysas/keysas-out";
const NEVER_SIGNED: &str = "/usr/share/keysas/neversigned";

#[derive(Serialize, Deserialize, Debug)]
pub struct GlobalStatus {
    health: Daemons,
    guichetin: GuichetState,
    guichettransit: bool,
    guichetout: GuichetState,
    has_signed_once: bool,
    keypair_generated: bool,
    ip: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Daemons {
    pub status_in: bool,
    pub status_transit: bool,
    pub status_out: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GuichetState {
    pub name: String,
    pub analysing: bool,
    pub files: Vec<String>,
}

fn landlock_sandbox() -> Result<(), RulesetError> {
    let abi = ABI::V1;
    let status = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))?
        .create()?
        // Read-only access to /usr, /etc and /dev.
        .add_rules(path_beneath_rules(
            &[
                "/usr", "/etc", "/dev", "/home", "/tmp", "/var", "/run", "/proc",
            ],
            AccessFs::from_read(abi),
        ))?
        .restrict_self()?;
    match status.ruleset {
        // The FullyEnforced case must be tested by the developer.
        RulesetStatus::FullyEnforced => println!("Landlock: Fully sandboxed."),
        RulesetStatus::PartiallyEnforced => println!("Landlock: Partially sandboxed."),
        // Users should be warned that they are not protected.
        RulesetStatus::NotEnforced => {
            println!("Landlock: Not sandboxed! Please update your kernel.");
        }
    }
    Ok(())
}

/// List files in a directory except hidden ones
///
/// # Errors
///
/// This function will return an error in the following situations:
///
/// * The provided `directory` does not exist.
/// * The process lacks permissions to read the contents of `directory`.
/// * The provided `directory` is not a directory.
/// * The internal regex for filtering hidden files fails to compile.
pub fn list_files(directory: &str) -> Result<Vec<String>> {
    let paths: std::fs::ReadDir = fs::read_dir(directory)?;
    let mut names = paths
        .filter_map(|entry| {
            entry.ok().and_then(|e| {
                e.path()
                    .file_name()
                    .and_then(|n| n.to_str().map(String::from))
            })
        })
        .collect::<Vec<String>>();
    // Not sending any files starting with dot like .bashrc
    let re = Regex::new(r"^\.([a-z])*")?;
    names.retain(|x| !re.is_match(x));
    Ok(names)
}

/// Get the status of the `keysas-in`, `keysas-transit` and `keysas-out` services.
///
/// # Panics
///
/// This function will panic if the `systemctl` command fails to execute for any of
/// the services.
///
/// # Errors
///
/// This function will return an error if the internal regex for parsing the
/// `systemctl` output fails to compile.
pub fn daemon_status() -> Result<[bool; 3]> {
    let mut state: [bool; 3] = [true, true, true];

    let output = Command::new("systemctl")
        .arg("status")
        .arg("keysas-in.service")
        .output()
        .expect("failed to get status for keysas-in");
    let status_in = String::from_utf8_lossy(&output.stdout);
    let re = Regex::new(r"Active:")?;
    state[0] = re.is_match(&status_in);

    let output = Command::new("systemctl")
        .arg("status")
        .arg("keysas-transit.service")
        .output()
        .expect("failed to get status for keysas-transit");
    let status_in = String::from_utf8_lossy(&output.stdout);
    let re = Regex::new(r"Active:")?;
    state[1] = re.is_match(&status_in);

    let output = Command::new("systemctl")
        .arg("status")
        .arg("keysas-out.service")
        .output()
        .expect("failed to get status for keysas-out");
    let status_in = String::from_utf8_lossy(&output.stdout);
    let re = Regex::new(r"Active: active")?;
    state[2] = re.is_match(&status_in);

    Ok(state)
}

fn parse_ip(s: &str) -> IResult<&str, &str> {
    take_until(":")(s)
}

fn get_ip() -> Result<Vec<String>> {
    let mut ips = Vec::new();
    let addrs = nix::ifaddrs::getifaddrs()?;
    let re = Regex::new(r"eth|enp")?;
    for ifaddr in addrs {
        if let Some(address) = ifaddr.address {
            let addr = address.to_string();
            let (_, ip) = parse_ip(&addr).unwrap();
            if re.is_match(&ifaddr.interface_name) && ip.parse::<Ipv4Addr>().is_ok() {
                ips.push(ip.to_string());
            }
        }
    }
    Ok(ips)
}

fn main() -> Result<()> {
    landlock_sandbox()?;
    let server = TcpListener::bind("127.0.0.1:3012")?;
    for stream in server.incoming() {
        println!("keysas-backend: Received a new websocket handshake.");
        let stream = match stream {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Failed to accept client connection: {e}");
                continue;
            }
        };
        spawn(move || -> Result<()> {
            let callback = |_req: &Request, response: Response| {
                log::info!("keysas-backend: Received a new websocket handshake.");
                //let headers = response.headers_mut();
                //headers.append("Sec-WebSocket-Protocol", "websocket".parse().unwrap());
                //println!("Response: {response:?}");
                Ok(response)
            };
            let mut websocket = accept_hdr(stream, callback)?;

            loop {
                let files_in = list_files(SAS_IN);
                let files_out = list_files(SAS_OUT);

                let mut fs_in = PathBuf::new();
                fs_in.push(SAS_IN);
                let is_empty_fs_in = fs_in.read_dir()?.next().is_none();

                let working_in = Path::new(LOCK_IN).exists() || !is_empty_fs_in;

                let working_out = Path::new(LOCK_OUT).exists();

                let working_transit = Path::new(LOCK_TRANSIT).exists();

                let health: Daemons = Daemons {
                    status_in: daemon_status()?[0],
                    status_transit: daemon_status()?[1],
                    status_out: daemon_status()?[2],
                };
                let guichet_state_in: GuichetState = GuichetState {
                    name: String::from("GUICHET-IN"),
                    analysing: working_in,
                    files: files_in?,
                };
                let guichet_state_out: GuichetState = GuichetState {
                    name: String::from("GUICHET-OUT"),
                    analysing: working_out,
                    files: files_out?,
                };
                let mut has_signed = false;

                if !Path::new(NEVER_SIGNED).exists() {
                    has_signed = true;
                }

                let orders = GlobalStatus {
                    health,
                    guichetin: guichet_state_in,
                    guichettransit: working_transit,
                    guichetout: guichet_state_out,
                    has_signed_once: has_signed,
                    keypair_generated: true,
                    ip: get_ip()?,
                };

                let serialized = serde_json::to_string(&orders)?;
                websocket.send(Message::Text(serialized.into()))?;
                thread::sleep(Duration::from_millis(300));
            }
        });
    }
    Ok(())
}

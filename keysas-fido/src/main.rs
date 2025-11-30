// SPDX-License-Identifier: GPL-3.0-only
/*
 * The "keysas-fido".
 *
 * (C) Copyright 2019-2025 Stephane Neveu
 *
 * This file contains the main function.
 */

#![forbid(unsafe_code)]
#![warn(unused_extern_crates)]
#![forbid(non_shorthand_field_patterns)]
#![warn(dead_code)]
#![warn(missing_debug_implementations)]
#![warn(missing_copy_implementations)]
#![warn(trivial_casts)]
#![warn(trivial_numeric_casts)]
#![warn(unstable_features)]
#![warn(unused_import_braces)]
#![warn(unused_qualifications)]
#![warn(variant_size_differences)]
#![forbid(trivial_bounds)]
#![warn(overflowing_literals)]
#![warn(deprecated)]

use clap::{ArgAction, Command as Clap_Command, arg, crate_version};
use rand::distributions::Alphanumeric;
use rand::{Rng, thread_rng};
use yubico_manager::Yubico;
use yubico_manager::config::{Command, Config};
use yubico_manager::config::{Mode, Slot};
use yubico_manager::configure::DeviceModeConfig;
use yubico_manager::hmacmode::HmacKey;
mod errors;
use crate::errors::Result;
use kv::Config as kvConfig;
use kv::{Raw, Store};
use std::fs::create_dir_all;
use std::path::Path;

fn store_key(name: &str, hex_string: &String) -> Result<bool> {
    // Configure the database
    if !Path::new("/etc/keysas/yubikey_db").is_dir() {
        create_dir_all("/etc/keysas/yubikey_db")?;
    }
    let cfg = kvConfig::new("/etc/keysas/yubikey_db");

    // Open the key/value store
    let store = Store::new(cfg)?;
    let enrolled_yubikeys = store.bucket::<String, String>(Some("Keysas"))?;

    if enrolled_yubikeys.get(hex_string)?.is_some() {
        Ok(false)
    } else {
        enrolled_yubikeys.set(hex_string, &name.to_string())?;
        Ok(true)
    }
}

fn remove_key(hex_string: &String) -> Result<()> {
    // Configure the database
    let cfg = kvConfig::new("/etc/keysas/yubikey_db");

    // Open the key/value store
    let store = Store::new(cfg)?;
    let enrolled_yubikeys = store.bucket::<Raw, Raw>(Some("Keysas"))?;
    enrolled_yubikeys.remove(&Raw::from(hex_string.as_bytes()))?;
    println!("If present, Yubikey was deleted.");
    Ok(())
}

fn manage_db(name: &str, enroll: bool, revoke: bool) -> Result<()> {
    let mut yubi = Yubico::new();

    if let Ok(device) = yubi.find_yubikey() {
        println!(
            "Vendor ID: {:?} Product ID {:?}",
            device.vendor_id, device.product_id
        );

        let config = Config::default_config()
            .set_vendor_id(device.vendor_id)
            .set_product_id(device.product_id)
            .set_variable_size(true)
            .set_mode(Mode::Sha1)
            .set_slot(Slot::Slot2);

        // Challenge can not be greater than 64 bytes
        let challenge = String::from("Keysas-Challenge");
        // In HMAC Mode, the result will always be the SAME for the SAME provided challenge
        let hmac_result = yubi.challenge_response_hmac(challenge.as_bytes(), config)?;

        let v: &[u8] = &hmac_result;
        let hex_string = hex::encode(v);
        if enroll && !revoke {
            match store_key(name, &hex_string.clone()) {
                Ok(true) => println!("Enrollment sucessfull for user {name}: {hex_string}"),
                Ok(false) => println!("Error: Yubikey already enrolled: {hex_string}"),
                Err(why) => println!("Error: {why:?}"),
            }
        } else if !enroll && revoke {
            remove_key(&hex_string)?;
        } else {
            println!("Error on revoke/enroll values !");
        }
    } else {
        println!("Yubikey not found");
    }
    Ok(())
}

fn init_yubikey() {
    let mut yubi = Yubico::new();

    if let Ok(device) = yubi.find_yubikey() {
        println!(
            "Found Yubikey: Vendor ID: {:?} Product ID {:?}",
            device.vendor_id, device.product_id
        );

        let config = Config::default_config()
            .set_vendor_id(device.vendor_id)
            .set_product_id(device.product_id)
            .set_command(Command::Configuration2);

        let rng = thread_rng();

        let require_press_button = true;

        let secret: String = rng
            .sample_iter(&Alphanumeric)
            .take(20)
            .map(char::from)
            .collect();
        let hmac_key: HmacKey = HmacKey::from_slice(secret.as_bytes());

        let mut device_config = DeviceModeConfig::default();
        device_config.challenge_response_hmac(&hmac_key, false, require_press_button);

        if let Err(err) = yubi.write_config(config, &mut device_config) {
            println!("Error write random secret: {err:?}");
        } else {
            println!("Your Yubikey is now configured using a random secret.");
        }
    } else {
        println!("Error: Yubikey not found.");
    }
}

fn main() -> Result<()> {
    // Start clap CLI definition
    let matches = Clap_Command::new("keysas-fido")
        .version(crate_version!())
        .author("Stephane N")
        .about("keysas-fido")
        .arg(
            arg!( -i --init <BOOL> "Sets the init mode for Yubikeys")
                .conflicts_with("enroll")
                .conflicts_with("revoke")
                .conflicts_with("name")
                .default_value("false")
                .action(ArgAction::SetTrue),
        )
        .arg(
            arg!( -e --enroll <BOOL> "Sets the enroll mode")
                .conflicts_with("init")
                .conflicts_with("revoke")
                .requires("name")
                .default_value("false")
                .action(ArgAction::SetTrue),
        )
        .arg(
            arg!( -n --name <NAME> "Sets the name to enroll the Yubikey")
                .requires("enroll")
                .default_value("false")
                .value_parser(clap::value_parser!(String)),
        )
        .arg(
            arg!( -r --revoke <BOOL> "Revoke a plugged Yubikey")
                .conflicts_with("init")
                .conflicts_with("enroll")
                .conflicts_with("name")
                .default_value("false")
                .action(ArgAction::SetTrue),
        )
        .get_matches();

    let init = matches.get_flag("init");
    let enroll = matches.get_flag("enroll");
    let revoke = matches.get_flag("revoke");
    let name = matches.get_one::<String>("name").unwrap();
    let name = name.trim();

    if init {
        init_yubikey();
    } else if enroll | revoke {
        manage_db(name, enroll, revoke)?;
    } else {
        println!("Error: Try keysas-fido --help");
    }

    Ok(())
}

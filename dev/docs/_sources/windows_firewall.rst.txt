********************
Windows USB firewall
********************

**Keysas** system also includes a **USB firewall** for Windows in order to check that:
- USB stick plugged on user laptop have been checked by a Keysas station;
- Files on the USB stick have been validated by the station.

.. warning::
 **USB firewall** has only been tested on Windows 10 laptop in debug mode for now.

Architecture
============

The firewall is composed of four elements:

- In kernel space
  - A USB bus filter driver
  - A minifilter (driver to filter system calls towards the filesystem)
- In userspace
  - A daemon supervising the two drivers and checks files and reports based on the system security policy
  - A tray application to allow the end user to control the security settings

Security Policy configuration
=============================

System security policy is configured from a TOML file at the base of the Daemon directory.
The policy is configured with:

- 'disable_unsigned_usb': if set to 'true', unsigned usb devices are allowed. No checks are performed on files on these devices.
- 'allow_user_usb_authorization': if set to 'true', grant the user the ability to manually allow unsigned USB devices. No checks are performed on files on these devices.
- 'allow_user_file_read': if set to 'true', grant the user the ability to manually allow read access to an unsigned file.
- 'allow_user_file_write': if set to 'true', grant the user the ability to manually allow write access to file on a USB device. 'allow_user_file_read' must also be set to true.

If parameters are missing from the configuration file, they are considered to be set to 'false'.

CA certificates must be provided to the daemon. The path to the pem files is given as arguments to the command line.

The complete command line is

```bash
./keysas-usbfilter-daemon.exe -config <path to security policy file> -ca_cl <path to CA ED25519 certificate> -ca_pq <path to CA Ml-Dsa certificate>
```

Installation
============

Driver compilation
------------------

The drivers have been tested on a Windows 10 laptop in debug mode (unsigned driver allowed).
They have been compiled with Microsoft Visual Studio 2022 with SDK and WDK version 10.0.22621.0.

Installer creation
------------------

An installer can be created with Inno Setup. For that all build artifacts must have been created (minifiler, driver and app), and then use Inno Setup build the script 'installer/keysas_firewall_install.iss'

Service and application compilation
-----------------------------------

The Keysas daemon and tray application have been compiled and tested on Windows 10 with the following dependencies:

- Rust toolchain: for example <https://learn.microsoft.com/en-us/windows/dev-environment/rust/setup>
- Clang toolchain: for example <https://rust-lang.github.io/rust-bindgen/requirements.html>
- CMake: <https://cmake.org/>
- Tauri: <https://tauri.app/>
- Npm: for example <https://docs.npmjs.com/downloading-and-installing-node-js-and-npm>

TODO List
----------

 This USB firewall application is still in progress:

- USB bus filter driver

  - [ ] Bus call interception: WIP

- Minifilter

  - [X] System call interception and filtering
  - [X] Track per file context
  - [X] Allow authorization changes
  - [X] Filter file open and create operations
  - [X] Filter write operation
  - [ ] Clean code: check IRQL, check paging, check fastIO, check sparse file API, check all flags in the pre-op filters...

- Daemon

  - [X] Check report and files
  - [X] Use CA certificate to check report certificate
  - [X] Enforce system security policy
  - [ ] Check USB devices

- Tray app

  - [X] Display files
  - [~] Display USB devices
  - [X] Allow authorization changes
  - [X] Add drop down menu for authorization selection:w


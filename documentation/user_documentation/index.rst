.. Keysas documentation master file, created by
   sphinx-quickstart on Wed Dec 30 08:13:07 2020.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

======
Keysas
======

**Keysas** is a modern decontamination station prototype, fast, which aims to be secure.

It provides an easy solution to verify your documents.
It can be used as a standalone “decontamination station” or act as a gateway to transfert untrusted files to higher security level networks. 
Untrusted files are scanned by an antivirus and you can manage and create your own Yara rules and add them easily to Keysas in order to inspect your files with more efficiency.
You can also create a whitelist of file types you want to transfert based on their **magic number** to filter more accurately. 


This software has been intentionally made to be as secure as possible using Rust programming langage, Secure Computing mode 2, strong sandboxing through systemd namespaces, LandLock and Apparmor.
However if you encounter any security issue, do not hesitate to contact us via `Github <https://github.com/r3dlight/keysas/>`_.

**Keysas** can be installed on Debian 12 (Bookworm) systems.

This software is written in `Rust <https://www.rust-lang.org/>`_, under `GPL-3.0 license <https://gitlab.com/r3dlight/keysas/-/blob/master/LICENSE>`_.

Learn more and contribute on `Github <https://github.com/r3dlight/keysas/>`_.

User documentation
------------------

.. toctree::
   :maxdepth: 3
   :caption: Contents:

   installation
   networkgw
   raspberry
   keysas-admin
   windows_firewall




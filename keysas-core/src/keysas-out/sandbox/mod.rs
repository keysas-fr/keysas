// SPDX-License-Identifier: GPL-3.0-only
/*
 * The "keysas-out".
 *
 * (C) Copyright 2019-2023 Stephane Neveu
 *
 * This file contains various funtions
 * to sandbox this binary using seccomp.
 */

use crate::CONFIG_DIRECTORY;
pub use anyhow::Result;
use landlock::{
    path_beneath_rules, Access, AccessFs, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetError,
    RulesetStatus, ABI,
};

#[cfg(target_os = "linux")]
use syscallz::{Context, Syscall};

#[cfg(not(tarpaulin_include))]
#[cfg(target_os = "linux")]
pub fn init() -> Result<()> {
    let mut ctx = Context::init()?;
    ctx.allow_syscall(Syscall::sendfile)?;
    ctx.allow_syscall(Syscall::write)?;
    ctx.allow_syscall(Syscall::openat)?;
    ctx.allow_syscall(Syscall::recvmsg)?;
    ctx.allow_syscall(Syscall::read)?;
    ctx.allow_syscall(Syscall::close)?;
    ctx.allow_syscall(Syscall::lseek)?;
    ctx.allow_syscall(Syscall::getrandom)?;
    ctx.allow_syscall(Syscall::mmap)?;
    ctx.allow_syscall(Syscall::statx)?;
    ctx.allow_syscall(Syscall::brk)?;
    ctx.allow_syscall(Syscall::mprotect)?;
    ctx.allow_syscall(Syscall::munmap)?;
    ctx.allow_syscall(Syscall::newfstatat)?;
    ctx.allow_syscall(Syscall::rt_sigaction)?;
    ctx.allow_syscall(Syscall::landlock_create_ruleset)?;
    ctx.allow_syscall(Syscall::landlock_add_rule)?;
    ctx.allow_syscall(Syscall::pread64)?;
    ctx.allow_syscall(Syscall::sigaltstack)?;
    ctx.allow_syscall(Syscall::prlimit64)?;
    #[cfg(target_arch = "x86_64")]
    ctx.allow_syscall(Syscall::poll)?;
    #[cfg(target_arch = "aarch64")]
    ctx.allow_syscall(Syscall::ppoll)?;
    ctx.allow_syscall(Syscall::ioctl)?;
    ctx.allow_syscall(Syscall::landlock_restrict_self)?;
    ctx.allow_syscall(Syscall::prctl)?;
    #[cfg(target_arch = "x86_64")]
    ctx.allow_syscall(Syscall::arch_prctl)?;
    ctx.allow_syscall(Syscall::sched_getaffinity)?;
    ctx.allow_syscall(Syscall::set_tid_address)?;
    ctx.allow_syscall(Syscall::rseq)?;
    ctx.allow_syscall(Syscall::set_robust_list)?;
    ctx.allow_syscall(Syscall::socket)?;
    #[cfg(target_arch = "x86_64")]
    ctx.allow_syscall(Syscall::access)?;
    #[cfg(target_arch = "aarch64")]
    ctx.allow_syscall(Syscall::faccessat)?;
    ctx.allow_syscall(Syscall::connect)?;
    ctx.allow_syscall(Syscall::execve)?;
    ctx.allow_syscall(Syscall::copy_file_range)?;
    ctx.allow_syscall(Syscall::clock_gettime)?;
    ctx.load()?;
    Ok(())
}

/// Setup the landlock sandboxing
pub fn landlock_sandbox(sas_out: &String) -> Result<(), RulesetError> {
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
        .add_rules(path_beneath_rules(&[sas_out], AccessFs::from_all(abi)))?
        .restrict_self()?;
    match status.ruleset {
        // The FullyEnforced case must be tested.
        RulesetStatus::FullyEnforced => {
            log::info!("Keysas-out is now fully sandboxed using Landlock !")
        }
        RulesetStatus::PartiallyEnforced => {
            log::warn!("Keysas-out is only partially sandboxed using Landlock !")
        }
        // Users should be warned that they are not protected.
        RulesetStatus::NotEnforced => {
            log::warn!("Keysas-out: Not sandboxed with Landlock ! Please update your kernel.")
        }
    }
    Ok(())
}

// SPDX-License-Identifier: GPL-3.0-only
/*
 * The "keysas-transit".
 *
 * (C) Copyright 2019-2025 Stephane Neveu
 *
 * This file contains various funtions
 * to sandbox this binary using seccomp.
 */
use crate::CONFIG_DIRECTORY;
pub use anyhow::Result;
use landlock::{
    ABI, Access, AccessFs, CompatLevel, Compatible, Ruleset, RulesetAttr, RulesetCreatedAttr,
    RulesetError, RulesetStatus, path_beneath_rules,
};
use std::path::Path;
use std::process;

#[cfg(target_os = "linux")]
use syscallz::{Context, Syscall};

#[cfg(target_os = "linux")]
pub fn init() -> Result<()> {
    let mut ctx = Context::init()?;
    ctx.allow_syscall(Syscall::sendto)?;
    ctx.allow_syscall(Syscall::read)?;
    ctx.allow_syscall(Syscall::fsync)?;
    ctx.allow_syscall(Syscall::write)?;
    ctx.allow_syscall(Syscall::connect)?;
    ctx.allow_syscall(Syscall::close)?;
    ctx.allow_syscall(Syscall::clock_nanosleep)?;
    ctx.allow_syscall(Syscall::rt_sigaction)?;
    ctx.allow_syscall(Syscall::recvfrom)?;
    ctx.allow_syscall(Syscall::munmap)?;
    ctx.allow_syscall(Syscall::recvmsg)?;
    ctx.allow_syscall(Syscall::lseek)?;
    ctx.allow_syscall(Syscall::socket)?;
    ctx.allow_syscall(Syscall::mmap)?;
    ctx.allow_syscall(Syscall::sendmsg)?;
    ctx.allow_syscall(Syscall::statx)?;
    ctx.allow_syscall(Syscall::rt_sigprocmask)?;
    #[cfg(target_arch = "x86_64")]
    ctx.allow_syscall(Syscall::dup2)?;
    #[cfg(target_arch = "aarch64")]
    ctx.allow_syscall(Syscall::dup3)?;
    ctx.allow_syscall(Syscall::newfstatat)?;
    ctx.allow_syscall(Syscall::fstat)?;
    ctx.allow_syscall(Syscall::madvise)?;
    ctx.allow_syscall(Syscall::accept4)?;
    ctx.allow_syscall(Syscall::bind)?;
    ctx.allow_syscall(Syscall::listen)?;
    ctx.allow_syscall(Syscall::mremap)?;
    ctx.allow_syscall(Syscall::brk)?;
    #[cfg(target_arch = "x86_64")]
    ctx.allow_syscall(Syscall::poll)?;
    #[cfg(target_arch = "aarch64")]
    ctx.allow_syscall(Syscall::ppoll)?;
    ctx.allow_syscall(Syscall::mprotect)?;
    ctx.allow_syscall(Syscall::ioctl)?;
    ctx.allow_syscall(Syscall::pread64)?;
    #[cfg(target_arch = "x86_64")]
    ctx.allow_syscall(Syscall::access)?;
    #[cfg(target_arch = "aarch64")]
    ctx.allow_syscall(Syscall::faccessat)?;
    ctx.allow_syscall(Syscall::execve)?;
    ctx.allow_syscall(Syscall::sigaltstack)?;
    ctx.allow_syscall(Syscall::prctl)?;
    #[cfg(target_arch = "x86_64")]
    ctx.allow_syscall(Syscall::arch_prctl)?;
    ctx.allow_syscall(Syscall::futex)?;
    ctx.allow_syscall(Syscall::sched_getaffinity)?;
    ctx.allow_syscall(Syscall::set_tid_address)?;
    ctx.allow_syscall(Syscall::openat)?;
    ctx.allow_syscall(Syscall::set_robust_list)?;
    ctx.allow_syscall(Syscall::prlimit64)?;
    ctx.allow_syscall(Syscall::getrandom)?;
    ctx.allow_syscall(Syscall::rseq)?;
    ctx.allow_syscall(Syscall::landlock_create_ruleset)?;
    ctx.allow_syscall(Syscall::landlock_add_rule)?;
    ctx.allow_syscall(Syscall::landlock_restrict_self)?;
    ctx.allow_syscall(Syscall::clock_gettime)?;
    ctx.allow_syscall(Syscall::exit_group)?;
    ctx.allow_syscall(Syscall::fstatfs)?;
    ctx.load()?;
    Ok(())
}

pub fn landlock_sandbox(rule_path: &String) -> Result<(), RulesetError> {
    let rules = Path::new(rule_path);
    let rules = match rules.parent() {
        Some(rules) => rules,
        None => {
            log::error!("Error getting Yara rules directory for Landlock");
            process::exit(1);
        }
    };
    let abi = ABI::V2;
    let status = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))?
        .set_compatibility(CompatLevel::HardRequirement)
        .create()?
        // Read-only access.
        .add_rules(path_beneath_rules(
            &[CONFIG_DIRECTORY, &rules.to_string_lossy()],
            AccessFs::from_read(abi),
        ))?
        .restrict_self()?;
    match status.ruleset {
        // The FullyEnforced case must be tested.
        RulesetStatus::FullyEnforced => {
            log::info!("Keysas-transit is now fully sandboxed using Landlock !")
        }
        RulesetStatus::PartiallyEnforced => {
            log::warn!("Keysas-transit is only partially sandboxed using Landlock !")
        }
        // Users should be warned that they are not protected.
        RulesetStatus::NotEnforced => {
            log::warn!("Keysas-transit: Not sandboxed with Landlock ! Please update your kernel.")
        }
    }
    Ok(())
}

// SPDX-License-Identifier: GPL-3.0-only
/*
 * The "keysas-in".
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
    RulesetStatus, path_beneath_rules,
};

#[cfg(target_os = "linux")]
use syscallz::{Context, Syscall};

#[cfg(target_os = "linux")]
pub fn init() -> Result<()> {
    let mut ctx = Context::init()?;
    ctx.allow_syscall(Syscall::clock_nanosleep)?;
    ctx.allow_syscall(Syscall::openat)?;
    ctx.allow_syscall(Syscall::getdents64)?;
    ctx.allow_syscall(Syscall::newfstatat)?;
    ctx.allow_syscall(Syscall::fstat)?;
    ctx.allow_syscall(Syscall::rt_sigprocmask)?;
    ctx.allow_syscall(Syscall::close)?;
    ctx.allow_syscall(Syscall::read)?;
    ctx.allow_syscall(Syscall::mmap)?;
    ctx.allow_syscall(Syscall::write)?;
    ctx.allow_syscall(Syscall::mprotect)?;
    ctx.allow_syscall(Syscall::munmap)?;
    ctx.allow_syscall(Syscall::statx)?;
    #[cfg(target_arch = "x86_64")]
    ctx.allow_syscall(Syscall::unlink)?;
    ctx.allow_syscall(Syscall::unlinkat)?;
    ctx.allow_syscall(Syscall::pread64)?;
    ctx.allow_syscall(Syscall::rt_sigaction)?;
    ctx.allow_syscall(Syscall::accept4)?;
    #[cfg(target_arch = "x86_64")]
    ctx.allow_syscall(Syscall::poll)?;
    #[cfg(target_arch = "aarch64")]
    ctx.allow_syscall(Syscall::ppoll)?;
    ctx.allow_syscall(Syscall::socket)?;
    ctx.allow_syscall(Syscall::ppoll)?;
    ctx.allow_syscall(Syscall::sendmsg)?;
    ctx.allow_syscall(Syscall::prlimit64)?;
    ctx.allow_syscall(Syscall::rseq)?;
    ctx.allow_syscall(Syscall::landlock_add_rule)?;
    #[cfg(target_arch = "x86_64")]
    ctx.allow_syscall(Syscall::arch_prctl)?;
    ctx.allow_syscall(Syscall::set_robust_list)?;
    ctx.allow_syscall(Syscall::set_tid_address)?;
    ctx.allow_syscall(Syscall::bind)?;
    ctx.allow_syscall(Syscall::landlock_restrict_self)?;
    ctx.allow_syscall(Syscall::ioctl)?;
    ctx.allow_syscall(Syscall::listen)?;
    ctx.allow_syscall(Syscall::prctl)?;
    ctx.allow_syscall(Syscall::getrandom)?;
    ctx.allow_syscall(Syscall::brk)?;
    #[cfg(target_arch = "x86_64")]
    ctx.allow_syscall(Syscall::access)?;
    #[cfg(target_arch = "aarch64")]
    ctx.allow_syscall(Syscall::faccessat)?;
    ctx.allow_syscall(Syscall::execve)?;
    ctx.allow_syscall(Syscall::sigaltstack)?;
    ctx.allow_syscall(Syscall::sched_getaffinity)?;
    ctx.allow_syscall(Syscall::landlock_create_ruleset)?;
    ctx.allow_syscall(Syscall::clock_gettime)?;
    ctx.load()?;
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn landlock_sandbox(sas_in: &String) -> Result<()> {
    use landlock::{PathBeneath, PathFd, make_bitflags};
    // Still using ABI v2 for now
    let abi = ABI::V2;
    let allow = make_bitflags!(AccessFs::{RemoveFile | RemoveDir | ReadFile | ReadDir});
    let status = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))?
        .create()?
        .set_compatibility(CompatLevel::HardRequirement)
        .add_rule(PathBeneath::new(PathFd::new(sas_in)?, allow))?
        .add_rules(path_beneath_rules(
            &[CONFIG_DIRECTORY],
            AccessFs::from_read(abi),
        ))?
        .restrict_self()?;
    match status.ruleset {
        // The FullyEnforced case must be tested.
        RulesetStatus::FullyEnforced => {
            log::info!("Keysas-in is now fully sandboxed using Landlock !")
        }
        RulesetStatus::PartiallyEnforced => {
            log::warn!("Keysas-in is only partially sandboxed using Landlock !")
        }
        // Users should be warned that they are not protected.
        RulesetStatus::NotEnforced => {
            log::warn!("Keysas-in: Not sandboxed with Landlock ! Please update your kernel.")
        }
    }
    Ok(())
}

//! Linux x86-64 syscall sandbox. This small unsafe OS adapter is in the TCB.
//! No filesystem/network/display APIs are available after enter(). Thread
//! creation is limited to CLONE_THREAD|CLONE_VM with the pthread flag set.
use crate::core::*;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub fn enter() -> Result<()> {
    unsafe {
        const LD: u16 = 0x20;
        const JEQ: u16 = 0x15;
        const RET: u16 = 0x06;
        const AND: u16 = 0x54;
        const ALLOW: u32 = 0x7fff0000;
        const KILL: u32 = 0x80000000;
        const ERRNO: u32 = 0x00050000;
        let stmt = |code, k| libc::sock_filter {
            code,
            jt: 0,
            jf: 0,
            k,
        };
        let jump = |k, jt, jf| libc::sock_filter {
            code: JEQ,
            jt,
            jf,
            k,
        };
        let mut code = vec![
            stmt(LD, 4),
            jump(0xc000003e, 1, 0),
            stmt(RET, KILL),
            stmt(LD, 0),
        ];
        // clone3's pointed-to argument block cannot be validated by seccomp BPF.
        // ENOSYS makes libc use the inspectable legacy clone operation.
        code.push(jump(libc::SYS_clone3 as u32, 0, 1));
        code.push(stmt(RET, ERRNO | libc::ENOSYS as u32));
        code.push(jump(libc::SYS_clone as u32, 0, 9));
        code.push(stmt(LD, 16));
        let flags = (libc::CLONE_VM
            | libc::CLONE_FS
            | libc::CLONE_FILES
            | libc::CLONE_SIGHAND
            | libc::CLONE_THREAD
            | libc::CLONE_SYSVSEM
            | libc::CLONE_SETTLS
            | libc::CLONE_PARENT_SETTID
            | libc::CLONE_CHILD_CLEARTID
            | libc::CLONE_CHILD_SETTID) as u32;
        code.push(stmt(AND, !flags));
        code.push(jump(0, 1, 0));
        code.push(stmt(RET, ERRNO | libc::EPERM as u32));
        code.push(stmt(LD, 16));
        let required = (libc::CLONE_THREAD | libc::CLONE_VM) as u32;
        code.push(stmt(AND, required));
        code.push(jump(required, 0, 1));
        code.push(stmt(RET, ALLOW));
        code.push(stmt(RET, ERRNO | libc::EPERM as u32));
        // The branch past clone's block must restore syscall-number A.
        code.push(stmt(LD, 0));
        let permitted = [
            libc::SYS_read,
            libc::SYS_write,
            libc::SYS_readv,
            libc::SYS_writev,
            libc::SYS_close,
            libc::SYS_fstat,
            libc::SYS_lseek,
            libc::SYS_mmap,
            libc::SYS_mprotect,
            libc::SYS_munmap,
            libc::SYS_mremap,
            libc::SYS_madvise,
            libc::SYS_brk,
            libc::SYS_futex,
            libc::SYS_clock_gettime,
            libc::SYS_clock_nanosleep,
            libc::SYS_nanosleep,
            libc::SYS_sched_yield,
            libc::SYS_sched_getaffinity,
            libc::SYS_getpid,
            libc::SYS_gettid,
            libc::SYS_getrandom,
            libc::SYS_rt_sigaction,
            libc::SYS_rt_sigprocmask,
            libc::SYS_rt_sigreturn,
            libc::SYS_sigaltstack,
            libc::SYS_set_robust_list,
            libc::SYS_rseq,
            libc::SYS_getrusage,
            libc::SYS_exit,
            libc::SYS_exit_group,
            libc::SYS_restart_syscall,
        ];
        for nr in permitted {
            code.push(jump(nr as u32, 0, 1));
            code.push(stmt(RET, ALLOW));
        }
        code.push(stmt(RET, ERRNO | libc::EPERM as u32));
        if libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32) != 0 {
            return Err(Error::Resource("close_range unavailable".into()));
        }
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err(Error::Resource("no_new_privs unavailable".into()));
        }
        let program = libc::sock_fprog {
            len: code.len() as u16,
            filter: code.as_mut_ptr(),
        };
        if libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program) != 0 {
            return Err(Error::Resource(format!(
                "seccomp unavailable: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }
}
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
pub fn enter() -> Result<()> {
    Err(Error::Resource(
        "no sandbox implementation for this platform".into(),
    ))
}

pub fn set_limits() -> Result<()> {
    #[cfg(target_os = "linux")]
    unsafe {
        let memory = libc::rlimit {
            rlim_cur: 512 * 1024 * 1024,
            rlim_max: 512 * 1024 * 1024,
        };
        if libc::setrlimit(libc::RLIMIT_AS, &memory) != 0 {
            return Err(Error::Resource("address-space limit unavailable".into()));
        }
        let cpu = libc::rlimit {
            rlim_cur: 3,
            rlim_max: 4,
        };
        if libc::setrlimit(libc::RLIMIT_CPU, &cpu) != 0 {
            return Err(Error::Resource("CPU limit unavailable".into()));
        }
        let core = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::setrlimit(libc::RLIMIT_CORE, &core) != 0 {
            return Err(Error::Resource("core dump limit unavailable".into()));
        }
    }
    Ok(())
}

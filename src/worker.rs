//! Host-side bounded one-job transport. The child has no authority over paths,
//! surface dimensions, deadlines, or which subsequent message it receives.
use crate::core::*;
use std::{
    io,
    os::fd::AsRawFd,
    process::{Command, Stdio},
    time::{Duration, Instant},
};
const MAX_JOB: usize = 20_000_000;
const MAX_TRACE: usize = 16_777_216;
fn poll(fd: i32, event: i16, deadline: Instant) -> Result<()> {
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(Error::Budget("worker deadline"));
        }
        let mut p = libc::pollfd {
            fd,
            events: event,
            revents: 0,
        };
        let n = unsafe {
            libc::poll(
                &mut p,
                1,
                left.as_millis().max(1).min(i32::MAX as u128) as i32,
            )
        };
        if n < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(Error::Resource("worker poll".into()));
        }
        if n == 0 {
            return Err(Error::Budget("worker deadline"));
        }
        if p.revents & event != 0 {
            return Ok(());
        }
        if p.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            return Err(Error::Resource("worker pipe closed".into()));
        }
    }
}
fn nonblocking(fd: i32) -> Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(Error::Resource("worker pipe flags".into()));
    }
    Ok(())
}
fn write_all(fd: i32, bytes: &[u8], deadline: Instant) -> Result<()> {
    let mut at = 0;
    while at < bytes.len() {
        poll(fd, libc::POLLOUT, deadline)?;
        let n = unsafe { libc::write(fd, bytes[at..].as_ptr().cast(), bytes.len() - at) };
        if n > 0 {
            at += n as usize;
        } else if n < 0
            && matches!(
                io::Error::last_os_error().kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            )
        {
            continue;
        } else {
            return Err(Error::Resource("worker write".into()));
        }
    }
    Ok(())
}
fn read_exact(fd: i32, bytes: &mut [u8], deadline: Instant) -> Result<()> {
    let mut at = 0;
    while at < bytes.len() {
        poll(fd, libc::POLLIN, deadline)?;
        let n = unsafe { libc::read(fd, bytes[at..].as_mut_ptr().cast(), bytes.len() - at) };
        if n > 0 {
            at += n as usize;
        } else if n < 0
            && matches!(
                io::Error::last_os_error().kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            )
        {
            continue;
        } else {
            return Err(Error::Resource("worker truncated response".into()));
        }
    }
    Ok(())
}
fn frame_len(fd: i32, deadline: Instant) -> Result<u64> {
    let mut b = [0u8; 8];
    read_exact(fd, &mut b, deadline)?;
    Ok(u64::from_le_bytes(b))
}
pub fn render(job: &[u8], width: u32, height: u32) -> Result<(Vec<u8>, Vec<u8>)> {
    if job.len() > MAX_JOB {
        return Err(Error::Budget("job bytes"));
    }
    let expected = image_len(
        width,
        height,
        width
            .checked_mul(4)
            .ok_or(Error::Budget("surface stride"))?,
        67_108_864,
    )?;
    let mut child = Command::new(
        std::env::current_exe().map_err(|_| Error::Resource("worker executable".into()))?,
    )
    .arg("worker-stdio")
    .env_clear()
    .env("LANG", "C.UTF-8")
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::null())
    .spawn()
    .map_err(|_| Error::Resource("worker spawn".into()))?;
    let result = (|| {
        let stdin = child.stdin.take().ok_or(Error::Invalid("worker stdin"))?;
        let stdout = child.stdout.take().ok_or(Error::Invalid("worker stdout"))?;
        nonblocking(stdin.as_raw_fd())?;
        nonblocking(stdout.as_raw_fd())?;
        let deadline = Instant::now() + Duration::from_secs(8);
        write_all(
            stdin.as_raw_fd(),
            &(job.len() as u64).to_le_bytes(),
            deadline,
        )?;
        write_all(stdin.as_raw_fd(), job, deadline)?;
        drop(stdin);
        let actual = frame_len(stdout.as_raw_fd(), deadline)?;
        if actual != expected as u64 {
            return Err(Error::Invalid("worker surface length"));
        }
        let mut rgba = vec![0; expected];
        read_exact(stdout.as_raw_fd(), &mut rgba, deadline)?;
        let trace_len = frame_len(stdout.as_raw_fd(), deadline)?;
        if trace_len > MAX_TRACE as u64 {
            return Err(Error::Budget("worker metadata"));
        }
        let mut trace = vec![0; trace_len as usize];
        read_exact(stdout.as_raw_fd(), &mut trace, deadline)?;
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    if !status.success() {
                        return Err(Error::Resource("worker failed".into()));
                    }
                    break;
                }
                Ok(None) => {
                    if Instant::now() >= deadline {
                        return Err(Error::Budget("worker exit deadline"));
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(_) => return Err(Error::Resource("worker wait".into())),
            }
        }
        Ok((rgba, trace))
    })();
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    result
}

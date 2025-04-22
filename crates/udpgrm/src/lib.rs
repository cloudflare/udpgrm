#![cfg(target_os = "linux")]

use crate::types::{UdpGrmDissectorOpts, UdpGrmSocketGen};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::{io, mem};

pub mod types;

pub trait UdpGrmSupport {
    /// Get working gen for socket group, ENOPROTOOPT if udpgrm cgroup hooks not present.
    fn get_working_gen(&self) -> io::Result<u32>;

    /// Get the socket generation for the socket.
    fn get_socket_gen(&self) -> io::Result<UdpGrmSocketGen>;

    /// Get the app number for the socket.
    fn get_app_number(&self) -> io::Result<u32>;

    /// Change the current working generation for this socket set.
    fn set_working_gen(&self, working_gen: u32) -> io::Result<()>;

    /// Set a dissector for socket group.
    fn set_dissector(&self, dissector_opts: UdpGrmDissectorOpts) -> io::Result<()>;

    /// Set the socket gen of this socket.
    fn set_socket_gen(&self, working_gen: u32) -> io::Result<()>;

    /// Set the app number of this socket.
    fn set_app_number(&self, app_no: u32) -> io::Result<()>;
}

impl UdpGrmSupport for std::net::UdpSocket {
    fn get_working_gen(&self) -> io::Result<u32> {
        fd_get_working_gen(self.as_fd())
    }

    fn get_socket_gen(&self) -> io::Result<UdpGrmSocketGen> {
        fd_get_socket_gen(self.as_fd())
    }

    fn get_app_number(&self) -> io::Result<u32> {
        fd_get_app_number(self.as_fd())
    }

    fn set_working_gen(&self, working_gen: u32) -> io::Result<()> {
        fd_set_working_gen(self.as_fd(), working_gen)
    }

    fn set_dissector(&self, dissector_opts: UdpGrmDissectorOpts) -> io::Result<()> {
        fd_set_dissector(self.as_fd(), dissector_opts)
    }

    fn set_socket_gen(&self, working_gen: u32) -> io::Result<()> {
        fd_set_socket_gen(self.as_fd(), working_gen)
    }

    fn set_app_number(&self, app_no: u32) -> io::Result<()> {
        fd_set_app_number(self.as_fd(), app_no)
    }
}

#[cfg(feature = "socket2")]
impl UdpGrmSupport for socket2::Socket {
    fn get_working_gen(&self) -> io::Result<u32> {
        fd_get_working_gen(self.as_fd())
    }

    fn get_socket_gen(&self) -> io::Result<UdpGrmSocketGen> {
        fd_get_socket_gen(self.as_fd())
    }

    fn get_app_number(&self) -> io::Result<u32> {
        fd_get_app_number(self.as_fd())
    }

    fn set_working_gen(&self, working_gen: u32) -> io::Result<()> {
        fd_set_working_gen(self.as_fd(), working_gen)
    }

    fn set_dissector(&self, dissector_opts: UdpGrmDissectorOpts) -> io::Result<()> {
        fd_set_dissector(self.as_fd(), dissector_opts)
    }

    fn set_socket_gen(&self, working_gen: u32) -> io::Result<()> {
        fd_set_socket_gen(self.as_fd(), working_gen)
    }

    fn set_app_number(&self, app_no: u32) -> io::Result<()> {
        fd_set_app_number(self.as_fd(), app_no)
    }
}

#[cfg(feature = "tokio")]
impl UdpGrmSupport for tokio::net::UdpSocket {
    fn get_working_gen(&self) -> io::Result<u32> {
        fd_get_working_gen(self.as_fd())
    }

    fn get_socket_gen(&self) -> io::Result<UdpGrmSocketGen> {
        fd_get_socket_gen(self.as_fd())
    }

    fn get_app_number(&self) -> io::Result<u32> {
        fd_get_app_number(self.as_fd())
    }

    fn set_working_gen(&self, working_gen: u32) -> io::Result<()> {
        fd_set_working_gen(self.as_fd(), working_gen)
    }

    fn set_dissector(&self, dissector_opts: UdpGrmDissectorOpts) -> io::Result<()> {
        fd_set_dissector(self.as_fd(), dissector_opts)
    }

    fn set_socket_gen(&self, working_gen: u32) -> io::Result<()> {
        fd_set_socket_gen(self.as_fd(), working_gen)
    }

    fn set_app_number(&self, app_no: u32) -> io::Result<()> {
        fd_set_app_number(self.as_fd(), app_no)
    }
}

fn set_opt<T: Copy>(
    sock: libc::c_int,
    opt: libc::c_int,
    val: libc::c_int,
    payload: T,
) -> io::Result<()> {
    unsafe {
        let payload = &payload as *const T as *const libc::c_void;
        cvt_linux_error(libc::setsockopt(
            sock,
            opt,
            val,
            payload as *const _,
            mem::size_of::<T>() as libc::socklen_t,
        ))?;
        Ok(())
    }
}

fn get_opt<T>(
    sock: libc::c_int,
    opt: libc::c_int,
    val: libc::c_int,
    payload: &mut T,
    size: &mut libc::socklen_t,
) -> io::Result<()> {
    unsafe {
        let payload = payload as *mut T as *mut libc::c_void;
        cvt_linux_error(libc::getsockopt(sock, opt, val, payload as *mut _, size))?;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn cvt_linux_error(t: i32) -> io::Result<i32> {
    if t == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(t)
    }
}

fn fd_set_dissector(socket: BorrowedFd, dissector_opts: UdpGrmDissectorOpts) -> io::Result<()> {
    set_opt(
        socket.as_raw_fd(),
        libc::IPPROTO_UDP,
        types::UDP_GRM_DISSECTOR,
        dissector_opts,
    )?;
    Ok(())
}

fn fd_set_socket_gen(socket: BorrowedFd, socket_gen: u32) -> io::Result<()> {
    set_opt(
        socket.as_raw_fd(),
        libc::IPPROTO_UDP,
        types::UDP_GRM_SOCKET_GEN,
        socket_gen,
    )?;
    Ok(())
}

fn fd_get_socket_gen(socket: BorrowedFd) -> io::Result<UdpGrmSocketGen> {
    let mut s_gen = UdpGrmSocketGen::default();
    let mut size = std::mem::size_of::<UdpGrmSocketGen>() as u32;

    get_opt(
        socket.as_raw_fd(),
        libc::IPPROTO_UDP,
        types::UDP_GRM_SOCKET_GEN,
        &mut s_gen,
        &mut size,
    )?;
    Ok(s_gen)
}

fn fd_set_working_gen(socket: BorrowedFd, working_gen: u32) -> io::Result<()> {
    set_opt(
        socket.as_raw_fd(),
        libc::IPPROTO_UDP,
        types::UDP_GRM_WORKING_GEN,
        working_gen,
    )?;
    Ok(())
}

/// Get working gen for socket, ENOPROTOOPT if not present.
fn fd_get_working_gen(socket: BorrowedFd) -> io::Result<u32> {
    let mut w_gen: u32 = 0;
    let mut size = std::mem::size_of::<u32>() as u32;

    get_opt(
        socket.as_raw_fd(),
        libc::IPPROTO_UDP,
        types::UDP_GRM_WORKING_GEN,
        &mut w_gen,
        &mut size,
    )?;
    Ok(w_gen)
}

fn fd_get_app_number(socket: BorrowedFd) -> io::Result<u32> {
    let mut app_no: u32 = 0;
    let mut size = std::mem::size_of::<u32>() as u32;

    get_opt(
        socket.as_raw_fd(),
        libc::IPPROTO_UDP,
        types::UDP_GRM_SOCKET_APP,
        &mut app_no,
        &mut size,
    )?;
    Ok(app_no)
}

fn fd_set_app_number(socket: BorrowedFd, app_no: u32) -> io::Result<()> {
    set_opt(
        socket.as_raw_fd(),
        libc::IPPROTO_UDP,
        types::UDP_GRM_SOCKET_APP,
        app_no,
    )?;
    Ok(())
}

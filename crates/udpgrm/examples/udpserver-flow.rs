use libc::{sockaddr, sockaddr_in, sockaddr_in6, sockaddr_storage, socklen_t, AF_INET, AF_INET6};
use nix;

use std::io;
use std::io::{IoSlice, IoSliceMut};

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket};
use std::os::fd::FromRawFd;
use std::os::fd::{AsFd, AsRawFd};
use udpgrm::types::{UdpGrmDissectorOpts, UdpGrmDissectorType};
use udpgrm::UdpGrmSupport;
fn std_addr_to_c(addr: &SocketAddr, out: &mut sockaddr_storage) -> socklen_t {
    let sin_port = addr.port().to_be();

    match addr {
        SocketAddr::V4(addr) => unsafe {
            let out_in = out as *mut _ as *mut sockaddr_in;

            let s_addr = u32::from_ne_bytes(addr.ip().octets());
            let sin_addr = libc::in_addr { s_addr };

            *out_in = sockaddr_in {
                sin_family: AF_INET as libc::sa_family_t,
                sin_addr,
                sin_port,
                sin_zero: std::mem::zeroed(),
            };

            std::mem::size_of::<sockaddr_in>() as socklen_t
        },

        SocketAddr::V6(addr) => unsafe {
            let out_in6 = out as *mut _ as *mut sockaddr_in6;

            let sin6_addr = libc::in6_addr {
                s6_addr: addr.ip().octets(),
            };

            *out_in6 = sockaddr_in6 {
                sin6_family: AF_INET6 as libc::sa_family_t,
                sin6_addr,
                sin6_port: sin_port,
                sin6_flowinfo: addr.flowinfo(),
                sin6_scope_id: addr.scope_id(),
            };

            std::mem::size_of::<sockaddr_in6>() as socklen_t
        },
    }
}

fn std_addr_from_c(addr: &sockaddr, addr_len: socklen_t) -> SocketAddr {
    match addr.sa_family as i32 {
        AF_INET => {
            assert!(addr_len as usize == std::mem::size_of::<sockaddr_in>());

            let in4 = unsafe { *(addr as *const _ as *const sockaddr_in) };
            let ip_addr = Ipv4Addr::from(u32::from_be(in4.sin_addr.s_addr));
            let port = u16::from_be(in4.sin_port);
            let out = SocketAddrV4::new(ip_addr, port);
            out.into()
        }

        AF_INET6 => {
            assert!(addr_len as usize == std::mem::size_of::<sockaddr_in6>());

            let in6 = unsafe { *(addr as *const _ as *const sockaddr_in6) };
            let ip_addr = Ipv6Addr::from(in6.sin6_addr.s6_addr);
            let port = u16::from_be(in6.sin6_port);
            let scope_id = in6.sin6_scope_id;
            let out = SocketAddrV6::new(ip_addr, port, in6.sin6_flowinfo, scope_id);
            out.into()
        }

        _ => unimplemented!("unsupported address type"),
    }
}

fn cvt_linux_error(t: i32) -> io::Result<i32> {
    if t == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(t)
    }
}

fn udp_socket_bind_with_control(
    addr: &SocketAddr,
    control: impl Fn(libc::c_int) -> io::Result<()>,
) -> io::Result<UdpSocket> {
    let fd = cvt_linux_error(unsafe {
        libc::socket(
            libc::AF_INET,
            libc::SOCK_DGRAM | libc::SOCK_NONBLOCK,
            0 as libc::c_int,
        )
    })?;

    control(fd)?;

    let mut ss: sockaddr_storage = unsafe { std::mem::zeroed() };
    let len = std_addr_to_c(&addr, &mut ss);

    cvt_linux_error(unsafe {
        libc::bind(
            fd,
            &ss as *const libc::sockaddr_storage as *const sockaddr,
            len,
        )
    })?;
    Ok(unsafe { UdpSocket::from_raw_fd(fd) })
}

fn get_so_cookie(raw_fd: i32) -> io::Result<u64> {
    let mut val: u64 = 0;
    //let val = &mut _val as *mut libc::c_void;
    let mut size: libc::socklen_t = std::mem::size_of::<u64>() as u32;
    cvt_linux_error(unsafe {
        libc::getsockopt(
            raw_fd,
            libc::SOL_SOCKET,
            libc::SO_COOKIE,
            &mut val as *mut u64 as *mut libc::c_void,
            &mut size,
        )
    })?;
    Ok(val)
}

fn main() {
    let listen_addr = "0.0.0.0:5201".parse::<SocketAddr>().unwrap();

    let sd = udp_socket_bind_with_control(&listen_addr, |raw_fd| {
        let one: u32 = 1;
        cvt_linux_error(unsafe {
            libc::setsockopt(
                raw_fd,
                libc::SOL_SOCKET,
                libc::SO_REUSEPORT,
                &one as *const _ as *const libc::c_void,
                std::mem::size_of::<u32>() as libc::socklen_t,
            )
        })?;

        if listen_addr.is_ipv4() {
            cvt_linux_error(unsafe {
                libc::setsockopt(
                    raw_fd,
                    libc::IPPROTO_IP,
                    libc::IP_PKTINFO,
                    &one as *const _ as *const libc::c_void,
                    std::mem::size_of::<u32>() as libc::socklen_t,
                )
            })?;
        } else {
            cvt_linux_error(unsafe {
                libc::setsockopt(
                    raw_fd,
                    libc::IPPROTO_IPV6,
                    libc::IPV6_RECVPKTINFO,
                    &one as *const _ as *const libc::c_void,
                    std::mem::size_of::<u32>() as libc::socklen_t,
                )
            })?;
            cvt_linux_error(unsafe {
                libc::setsockopt(
                    raw_fd,
                    libc::IPPROTO_IPV6,
                    libc::IPV6_V6ONLY,
                    &one as *const _ as *const libc::c_void,
                    std::mem::size_of::<u32>() as libc::socklen_t,
                )
            })?;
        }

        Ok(())
    })
    .unwrap();

    let mut opts = UdpGrmDissectorOpts::default();
    opts.dissector_type = UdpGrmDissectorType::DissectorFlow;
    match sd.set_dissector(opts) {
        Ok(_) => (),
        Err(e) if e.raw_os_error().unwrap() == libc::ENOPROTOOPT => {
            panic!("[!] cgroups hooks not loaded");
        }
        Err(e) => {
            panic!("Failed to get working generation: {e}");
        }
    }

    let gen = sd.get_working_gen().unwrap();
    sd.set_socket_gen(gen + 1).unwrap();
    sd.set_working_gen(gen + 1).unwrap();

    let raw_fd = sd.as_raw_fd();
    loop {
        let mut readfds = nix::sys::select::FdSet::new();
        readfds.insert(sd.as_fd());
        let _ = nix::sys::select::select(raw_fd + 1, &mut readfds, None, None, None);
        for fd in readfds.fds(None) {
            let mut buf = [0; 4096];
            let x = IoSliceMut::new(&mut buf);
            let io_vec = &mut [x];
            let mut cmsg_buf = nix::cmsg_space!([u8; 512]);
            let msg: nix::sys::socket::RecvMsg<nix::sys::socket::SockaddrStorage> =
                nix::sys::socket::recvmsg(
                    fd.as_raw_fd(),
                    io_vec,
                    Some(&mut cmsg_buf),
                    nix::sys::socket::MsgFlags::empty(),
                )
                .unwrap();

            use nix::sys::socket::ControlMessage;
            use nix::sys::socket::ControlMessageOwned;

            let mut tx_cmsgs: Vec<nix::sys::socket::ControlMessage> = vec![];

            let mut ipv4_pi = None;
            let mut ipv6_pi = None;
            for cmsg in msg.cmsgs() {
                match cmsg {
                    ControlMessageOwned::Ipv4PacketInfo(pi) => {
                        ipv4_pi = Some(pi);
                    }
                    ControlMessageOwned::Ipv6PacketInfo(pi) => {
                        ipv6_pi = Some(pi);
                    }
                    x => panic!("Unknown control message {:?}", x),
                }
            }
            let pi4;
            if let Some(pi) = ipv4_pi {
                pi4 = pi;
                tx_cmsgs.push(ControlMessage::Ipv4PacketInfo(&pi4));
            }
            let pi6;
            if let Some(pi) = ipv6_pi {
                pi6 = pi;
                tx_cmsgs.push(ControlMessage::Ipv6PacketInfo(&pi6));
            }

            let so_cookie = get_so_cookie(fd.as_raw_fd()).unwrap();

            let s = format!("{:#08x} ", so_cookie);
            let b = &msg.iovs().next().unwrap();
            let iov = &[IoSlice::new(s.as_bytes()), IoSlice::new(b)];

            let _ = nix::sys::socket::sendmsg(
                fd.as_raw_fd(),
                iov,
                &tx_cmsgs,
                nix::sys::socket::MsgFlags::empty(),
                msg.address.as_ref(),
            );

            println!("{:?} {:?}", fd, msg);
        }
    }
}

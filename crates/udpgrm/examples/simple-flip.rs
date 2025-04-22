use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use udpgrm::types::{UdpGrmDissectorOpts, UdpGrmDissectorType};
use udpgrm::UdpGrmSupport;

fn main() {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();

    socket.set_reuse_port(true).unwrap();

    socket
        .bind(&SockAddr::from(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            5222,
        )))
        .unwrap();

    let mut opts = UdpGrmDissectorOpts::default();

    opts.dissector_type = UdpGrmDissectorType::DissectorFlow;
    opts.flow_entry_timeout_sec = 120;

    match socket.set_dissector(opts) {
        Ok(_) => {
            // get current working generation
            let gen = socket.get_working_gen().unwrap();

            // set socket to next generation
            socket.set_socket_gen(gen + 1).unwrap();

            // Give udpgrm daemon a moment to register the socket
            let mut rgen = Default::default();
            for i in 0..8 {
                rgen = socket.get_socket_gen().unwrap();
                if rgen.socket_idx != 0xffffffff {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(1) * 2_u32.pow(i));
            }

            assert_ne!(rgen.socket_idx, 0xffffffff);

            // bump socket group generation
            socket.set_working_gen(gen + 1).unwrap();

            // verify working generation was bumped
            let gen2 = socket.get_working_gen().unwrap();

            assert_eq!(gen + 1, gen2);

            println!("Yay, it worked!");
        }
        Err(e) if e.raw_os_error().unwrap() == libc::ENOPROTOOPT => {
            println!("cgroups hooks not loaded");
        }
        Err(e) => {
            eprintln!("Failed to get working generation: {e}");
        }
    }
}

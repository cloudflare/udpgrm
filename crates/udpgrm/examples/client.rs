// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

use clap::Parser;
use ring::rand::SecureRandom;
use ring::rand::SystemRandom;

const MAX_DATAGRAM_SIZE: usize = 1350;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    verbose: bool,

    #[arg(short, long, value_name = "IP:PORT", value_parser = clap::value_parser!(std::net::SocketAddr))]
    target: std::net::SocketAddr,

    #[arg(value_name = "URL")]
    url: Vec<url::Url>,

    #[arg(short, long)]
    deterministic: bool,
}

fn main() {
    let args = Args::parse();

    let mut buf = [0; 65535];
    let mut out = [0; MAX_DATAGRAM_SIZE];

    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
    // *CAUTION*: this should not be set to `false` in production!!!
    config.verify_peer(false);

    config
        .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
        .unwrap();

    config.set_max_idle_timeout(5000);
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_stream_data_uni(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    config.set_disable_active_migration(true);

    for url in args.url {
        let url = url;

        // Setup the event loop.
        let mut poll = mio::Poll::new().unwrap();
        let mut events = mio::Events::with_capacity(1024);

        let bind_addr = match args.target {
            std::net::SocketAddr::V4(_) => "0.0.0.0:0",
            std::net::SocketAddr::V6(_) => "[::]:0",
        };

        let mut socket = mio::net::UdpSocket::bind(bind_addr.parse().unwrap()).unwrap();
        poll.registry()
            .register(&mut socket, mio::Token(0), mio::Interest::READABLE)
            .unwrap();

        let mut http3_conn = None;

        let mut scid = [0; quiche::MAX_CONN_ID_LEN];
        if args.deterministic {
            scid[..4].copy_from_slice(b"\xDE\xAD\xBA\xBE");
        } else {
            SystemRandom::new().fill(&mut scid[..]).unwrap();
        }

        let scid = quiche::ConnectionId::from_ref(&scid);

        // Get local address.
        let local_addr = socket.local_addr().unwrap();

        // Create a QUIC connection and initiate handshake.
        let mut conn =
            quiche::connect(url.domain(), &scid, local_addr, args.target, &mut config).unwrap();

        let (write, send_info) = conn.send(&mut out).expect("initial send failed");

        while let Err(e) = socket.send_to(&out[..write], send_info.to) {
            if e.kind() == std::io::ErrorKind::WouldBlock {
                continue;
            }

            panic!("send() failed: {:?}", e);
        }

        let h3_config = quiche::h3::Config::new().unwrap();

        let mut path = String::from(url.path());

        if let Some(query) = url.query() {
            path.push('?');
            path.push_str(query);
        }

        let req = vec![
            quiche::h3::Header::new(b":method", b"GET"),
            quiche::h3::Header::new(b":scheme", url.scheme().as_bytes()),
            quiche::h3::Header::new(b":authority", url.host_str().unwrap().as_bytes()),
            quiche::h3::Header::new(b":path", path.as_bytes()),
            quiche::h3::Header::new(b"user-agent", b"quiche"),
        ];

        let mut req_sent = false;

        loop {
            poll.poll(&mut events, conn.timeout()).unwrap();

            'read: loop {
                if events.is_empty() {
                    conn.on_timeout();

                    break 'read;
                }

                let (len, from) = match socket.recv_from(&mut buf) {
                    Ok(v) => v,

                    Err(e) => {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            break 'read;
                        }

                        panic!("recv() failed: {:?}", e);
                    }
                };

                let recv_info = quiche::RecvInfo {
                    to: local_addr,
                    from,
                };

                // Process potentially coalesced packets.
                let _read = match conn.recv(&mut buf[..len], recv_info) {
                    Ok(v) => v,

                    Err(e) => {
                        println!("[!] recv failed: {:?}", e);
                        continue 'read;
                    }
                };
            }

            if conn.is_closed() {
                break;
            }

            // Create a new HTTP/3 connection once the QUIC connection is established.
            if conn.is_established() && http3_conn.is_none() {
                http3_conn = Some(
                    quiche::h3::Connection::with_transport(&mut conn, &h3_config)
                        .expect("Unable to create HTTP/3 connection, check the server's uni stream limit and window size"),
                );
            }

            // Send HTTP requests once the QUIC connection is established, and until
            // all requests have been sent.
            if let Some(h3_conn) = &mut http3_conn {
                if !req_sent {
                    h3_conn.send_request(&mut conn, &req, true).unwrap();

                    req_sent = true;
                }
            }

            if let Some(http3_conn) = &mut http3_conn {
                // Process HTTP/3 events.
                loop {
                    match http3_conn.poll(&mut conn) {
                        Ok((_stream_id, quiche::h3::Event::Headers { .. })) => {}

                        Ok((stream_id, quiche::h3::Event::Data)) => {
                            while let Ok(read) =
                                http3_conn.recv_body(&mut conn, stream_id, &mut buf)
                            {
                                print!("{}", unsafe {
                                    std::str::from_utf8_unchecked(&buf[..read])
                                });
                            }
                        }

                        Ok((_stream_id, quiche::h3::Event::Finished)) => {
                            conn.close(true, 0x100, b"kthxbye").unwrap();
                        }

                        Ok((_stream_id, quiche::h3::Event::Reset(e))) => {
                            println!("[!] request was reset by peer with {}, closing...", e);

                            conn.close(true, 0x100, b"kthxbye").unwrap();
                        }

                        Ok((_, quiche::h3::Event::PriorityUpdate)) => unreachable!(),

                        Ok((_goaway_id, quiche::h3::Event::GoAway)) => {}

                        Err(quiche::h3::Error::Done) => {
                            break;
                        }

                        Err(e) => {
                            println!("[!] HTTP/3 processing failed: {:?}", e);

                            break;
                        }
                    }
                }
            }

            loop {
                let (write, send_info) = match conn.send(&mut out) {
                    Ok(v) => v,

                    Err(quiche::Error::Done) => {
                        break;
                    }

                    Err(e) => {
                        println!("[!] send failed: {:?}", e);

                        conn.close(false, 0x1, b"fail").ok();
                        break;
                    }
                };

                if let Err(e) = socket.send_to(&out[..write], send_info.to) {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        break;
                    }

                    panic!("send() failed: {:?}", e);
                }
            }

            if conn.is_closed() {
                break;
            }
        }
    }
}

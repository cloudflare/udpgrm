use boring::ssl::{SslContextBuilder, SslFiletype, SslMethod};
use clap::Parser;
use futures::stream::SelectAll;
use futures::{SinkExt as _, StreamExt as _};
use std::collections::HashMap;
use std::error::Error;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::sync::RwLock;
use std::sync::{Arc, Mutex, OnceLock};
use tokio_quiche::buf_factory::BufFactory;
use tokio_quiche::http3::driver::{H3Event, IncomingH3Headers, OutboundFrame, ServerH3Event};
use tokio_quiche::http3::settings::Http3Settings;
use tokio_quiche::listen_with_capabilities;
use tokio_quiche::metrics::DefaultMetrics;
use tokio_quiche::quic::ConnectionHook;
use tokio_quiche::quiche::h3;
use tokio_quiche::quiche::ConnectionId;
use tokio_quiche::settings::QuicSettings;
use tokio_quiche::settings::{Hooks, TlsCertificatePaths};
use tokio_quiche::socket::QuicListener;
use tokio_quiche::socket::SocketCapabilities;
use tokio_quiche::{ConnectionParams, ServerH3Controller, ServerH3Driver};
use udpgrm::UdpGrmSupport;

use socket2::{Domain, Protocol, Socket, Type};

static CURRENT_SNI: Mutex<Option<String>> = Mutex::new(None);
static CURRENT_SOCKET_COOKIE: Mutex<Option<u64>> = Mutex::new(None);

static COOKIE_MAP: OnceLock<RwLock<HashMap<u64, u64>>> = OnceLock::new();


// udpgrm cookie to socket cookie
pub fn set_cookie(key: u64, value: u64) {
    let cookie_map = COOKIE_MAP.get_or_init(|| RwLock::new(HashMap::new()));
    let mut map = cookie_map.write().unwrap();
    map.insert(key, value);
}

pub fn get_cookie(key: u64) -> Option<u64> {
    let cookie_map = COOKIE_MAP.get_or_init(|| RwLock::new(HashMap::new()));
    let map = cookie_map.read().unwrap();
    map.get(&key).copied()
}

struct CallbackConnectionHook {}

impl ConnectionHook for CallbackConnectionHook {
    fn create_custom_ssl_context_builder(
        &self,
        settings: TlsCertificatePaths<'_>,
    ) -> Option<SslContextBuilder> {
        let mut ssl_ctx_builder = SslContextBuilder::new(SslMethod::tls()).ok()?;
        ssl_ctx_builder
            .set_private_key_file(settings.private_key, SslFiletype::PEM)
            .unwrap();

        ssl_ctx_builder
            .set_certificate_chain_file(settings.cert)
            .unwrap();

        ssl_ctx_builder.set_servername_callback(|ssl, _alert| {
            let servername = ssl
                .servername(boring::ssl::NameType::HOST_NAME)
                .map(|name| name.to_string());

            let mut sni = CURRENT_SNI.lock().unwrap();
            *sni = servername;

            Ok(())
        });
        Some(ssl_ctx_builder)
    }
}

async fn create_socket_with_reuse_addr(
    addr: &std::net::SocketAddr,
) -> std::io::Result<tokio::net::UdpSocket> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;
    let sock_addr = socket2::SockAddr::from(*addr);
    socket.bind(&sock_addr)?;

    let std_socket = socket.into();
    let tokio_socket = tokio::net::UdpSocket::from_std(std_socket)?;
    Ok(tokio_socket)
}

pub fn get_socket_cookie(socket: &tokio::net::UdpSocket) -> u64 {
    let fd = socket.as_raw_fd();
    let mut cookie: u64 = 0;
    let mut len = std::mem::size_of::<u64>() as libc::socklen_t;

    unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_COOKIE,
            &mut cookie as *mut u64 as *mut libc::c_void,
            &mut len,
        )
    };
    cookie
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, value_name = "FILE")]
    crt: String,

    #[arg(short, long, value_name = "FILE")]
    key: String,

    #[arg(short, long, value_name = "IP:PORT", value_parser = clap::value_parser!(std::net::SocketAddr))]
    listen: Vec<std::net::SocketAddr>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    let hooks = Hooks {
        connection_hook: Some(Arc::new(CallbackConnectionHook {})),
    };

    let mut sockets = Vec::new();
    // Before --listen handling
    sockets.extend(find_activated_sockets());

    for addr in &args.listen {
        let socket = create_socket_with_reuse_addr(addr).await?;
        println!("[ ] Listening on {}", addr);
        sockets.push(socket);
    }
    if sockets.is_empty() {
        panic!("[!] no sockets to listen on. pass --listen");
    }

    let mut quic_listeners = Vec::new();
    for sd in sockets {
        let socket_cookie = get_socket_cookie(&sd);

        let std = sd.into_std().unwrap();
        let udpgrm_cookie = match std.get_socket_gen().map(|x| x.grm_cookie) {
            Ok(v) => v as u64,
            Err(_) => socket_cookie,
        };

        set_cookie(udpgrm_cookie, socket_cookie);

        let listener = QuicListener {
            socket: tokio::net::UdpSocket::from_std(std).unwrap(),
            socket_cookie: udpgrm_cookie,
            capabilities: SocketCapabilities::default(),
        };
        quic_listeners.push(listener);
    }

    let mut quic_settings: QuicSettings = Default::default();
    quic_settings.handshake_timeout = Some(std::time::Duration::from_secs(30));

    let listeners = listen_with_capabilities(
        quic_listeners,
        ConnectionParams::new_server(
            quic_settings,
            tokio_quiche::settings::TlsCertificatePaths {
                cert: &args.crt,
                private_key: &args.key,
                kind: tokio_quiche::settings::CertificateKind::X509,
            },
            hooks,
        ),
        DCIDGenerator,
        DefaultMetrics,
    )?;

    // Combine all listeners into a single stream
    let mut all_listeners = SelectAll::new();
    for listener in listeners {
        all_listeners.push(listener);
    }

    while let Some(conn) = all_listeners.next().await {
        let (driver, controller) = ServerH3Driver::new(Http3Settings::default());
        conn?.start(driver);
        tokio::spawn(handle_connection(controller));
    }
    Ok(())
}

async fn handle_connection(mut controller: ServerH3Controller) {
    while let Some(ServerH3Event::Core(event)) = controller.event_receiver_mut().recv().await {
        match event {
            H3Event::IncomingHeaders(IncomingH3Headers {
                mut send, headers, ..
            }) => {
                let cookie_value = {
                    let guard = CURRENT_SOCKET_COOKIE.lock().unwrap();
                    guard.unwrap_or(0) // Get the value and handle None case
                };
                println!(
                    "socket_cookie #{:08x} sni {:?} headers {:?} ",
                    cookie_value,
                    CURRENT_SNI.lock().unwrap(),
                    headers,
                );
                send.send(OutboundFrame::Headers(vec![h3::Header::new(
                    b":status", b"200",
                )]))
                .await
                .unwrap();

                let body = format!("#{:08x}\n", cookie_value);
                send.send(OutboundFrame::body(
                    BufFactory::buf_from_slice(body.as_bytes()),
                    true,
                ))
                .await
                .unwrap();
            }
            event => {
                println!("event: {event:?}");
            }
        }
    }
}

const MAX_GAP: i32 = 32;

fn find_activated_sockets() -> Vec<tokio::net::UdpSocket> {
    let mut gap = 0;
    let mut udp_sockets = Vec::new();

    for fd in 3.. {
        // Try to duplicate the fd to check if it's valid
        let dup_fd = unsafe { libc::dup(fd) };

        if dup_fd == -1 {
            gap += 1;
            if gap > MAX_GAP {
                break;
            }
            continue;
        }
        unsafe {
            libc::close(dup_fd);
        }

        gap = 0;

        // Check if it's a socket
        let mut domain: i32 = 0;
        let mut sock_type: i32 = 0;
        let mut protocol: i32 = 0;
        let mut len = std::mem::size_of::<i32>() as libc::socklen_t;
        unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_DOMAIN,
                &mut domain as *mut i32 as *mut libc::c_void,
                &mut len,
            );
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_TYPE,
                &mut sock_type as *mut i32 as *mut libc::c_void,
                &mut len,
            );
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PROTOCOL,
                &mut protocol as *mut i32 as *mut libc::c_void,
                &mut len,
            );
        }

        // If it's a UDP socket, add it to our vector
        if (domain == libc::AF_INET || domain == libc::AF_INET6)
            && sock_type == libc::SOCK_DGRAM
            && protocol == libc::IPPROTO_UDP
        {
            let socket = {
                let std_socket = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
                std_socket.set_nonblocking(true).unwrap();
                tokio::net::UdpSocket::from_std(std_socket).unwrap()
            };
            let la = socket.local_addr().unwrap();
            println!("[ ] Socket {:?} from activation", la);
            udp_sockets.push(socket);
        }
    }
    udp_sockets
}

#[derive(Debug, Clone, Default)]
pub struct DCIDGenerator;

const MAX_CONN_ID_LEN: usize = 20;

impl tokio_quiche::ConnectionIdGenerator<'static> for DCIDGenerator {
    fn new_connection_id(&self, udpgrm_cookie: u64) -> tokio_quiche::quiche::ConnectionId<'static> {
        let mut scid = vec![0; MAX_CONN_ID_LEN];
        boring::rand::rand_bytes(&mut scid).unwrap();

        scid[0] = 1;

        // udpgrm socket cookie is 2 bytes
        let udpgrm_cookie_be = (udpgrm_cookie as u16).to_be_bytes();
        scid[1] = udpgrm_cookie_be[0];
        scid[2] = udpgrm_cookie_be[1];
        println!("[ ] cookie {:x?}", scid);

        let socket_cookie = get_cookie(udpgrm_cookie);
        let mut current_socket_cookie = CURRENT_SOCKET_COOKIE.lock().unwrap();
        *current_socket_cookie = socket_cookie;

        ConnectionId::from(scid)
    }

    /// Performs no verification, because this generator can create
    /// any valid connection ID.
    fn verify_connection_id(
        &self,
        _socket_cookie: u64,
        _cid: &tokio_quiche::quiche::ConnectionId<'_>,
    ) -> tokio_quiche::QuicResult<()> {
        //println!("dcid verify {:08x}", socket_cookie);
        Ok(())
    }
}

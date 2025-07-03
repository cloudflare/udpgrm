// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

use clap::Parser;
use std::error::Error;
use tokio_quiche::http3::driver::{ClientH3Event, H3Event, InboundFrame, IncomingH3Headers};
use tokio_quiche::quiche::h3;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    verbose: bool,

    #[arg(short, long, value_name = "IP:PORT", value_parser = clap::value_parser!(std::net::SocketAddr))]
    target: std::net::SocketAddr,

    #[arg(value_name = "URL")]
    url: Vec<url::Url>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    for url in args.url {
        let host = url.host_str().unwrap_or("").to_string();
        let path = url.path();
        let query = url.query().map(|q| format!("?{}", q)).unwrap_or_default();
        let full_path = format!("{}{}", path, query);

        let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(args.target).await.unwrap();

        println!("target {} host {}\n", args.target, host);
        let (_, mut controller) = tokio_quiche::quic::connect(socket, Some(&host))
            .await
            .unwrap();
        println!("post\n");

        controller
            .request_sender()
            .send(tokio_quiche::http3::driver::NewClientRequest {
                request_id: 1,
                headers: vec![
                    h3::Header::new(b":method", b"GET"),
                    h3::Header::new(b":scheme", url.scheme().as_bytes()),
                    h3::Header::new(b":authority", host.as_bytes()),
                    h3::Header::new(b":path", full_path.as_bytes()),
                ],
                body_writer: None,
            })
            .unwrap();

        while let Some(event) = controller.event_receiver_mut().recv().await {
            match event {
                ClientH3Event::Core(H3Event::IncomingHeaders(IncomingH3Headers {
                    stream_id: _,
                    headers,
                    mut recv,
                    ..
                })) => {
                    if args.verbose {
                        println!("{:?}", headers);
                    }
                    'body: while let Some(frame) = recv.recv().await {
                        match frame {
                            InboundFrame::Body(pooled, fin) => {
                                match std::str::from_utf8(&pooled) {
                                    Ok("") => (),
                                    Ok(body) => print!("{}", body),
                                    Err(_) => (),
                                }
                                if fin {
                                    break 'body;
                                }
                            }
                            InboundFrame::Datagram(_pooled) => {}
                        }
                    }
                }
                ClientH3Event::Core(H3Event::BodyBytesReceived { fin: true, .. }) => {
                    break;
                }
                ClientH3Event::Core(_event) => (),
                ClientH3Event::NewOutboundRequest { .. } => (),
            }
        }
    }
    Ok(())
}

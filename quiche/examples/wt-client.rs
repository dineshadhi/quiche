// Copyright (C) 2024, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#[macro_use]
extern crate log;

use quiche::h3::NameValue;

use ring::rand::*;

const MAX_DATAGRAM_SIZE: usize = 1350;

fn main() {
    env_logger::init();
    let mut buf = [0; 65535];
    let mut out = [0; MAX_DATAGRAM_SIZE];

    let mut args = std::env::args();

    let cmd = &args.next().unwrap();

    if args.len() != 1 {
        println!("Usage: {cmd} URL");
        println!("\nSee tools/apps/ for more complete implementations.");
        return;
    }

    let url = url::Url::parse(&args.next().unwrap()).unwrap();

    // Setup the event loop.
    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);

    // Resolve server address.
    let peer_addr = url.socket_addrs(|| None).unwrap()[0];

    // Bind to INADDR_ANY or IN6ADDR_ANY depending on the IP family of the
    // server address.
    let bind_addr = match peer_addr {
        std::net::SocketAddr::V4(_) => "0.0.0.0:0",
        std::net::SocketAddr::V6(_) => "[::]:0",
    };

    let mut socket =
        mio::net::UdpSocket::bind(bind_addr.parse().unwrap()).unwrap();
    poll.registry()
        .register(&mut socket, mio::Token(0), mio::Interest::READABLE)
        .unwrap();

    // Create the configuration for the QUIC connection.
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
    config.enable_dgram(true, 100, 100);

    let mut h3_config = quiche::h3::Config::new().unwrap();
    h3_config.enable_webtransport_draft02(true);

    // Generate a random source connection ID for the connection.
    let mut scid = [0; quiche::MAX_CONN_ID_LEN];
    SystemRandom::new().fill(&mut scid[..]).unwrap();

    let scid = quiche::ConnectionId::from_ref(&scid);

    // Get local address.
    let local_addr = socket.local_addr().unwrap();

    // Create a QUIC connection and initiate handshake.
    let mut conn =
        quiche::connect(url.domain(), &scid, local_addr, peer_addr, &mut config)
            .unwrap();

    info!(
        "connecting to {:} from {:} with scid {}",
        peer_addr,
        socket.local_addr().unwrap(),
        hex_dump(&scid)
    );

    let (write, send_info) = conn.send(&mut out).expect("initial send failed");

    while let Err(e) = socket.send_to(&out[..write], send_info.to) {
        if e.kind() == std::io::ErrorKind::WouldBlock {
            debug!("send() would block");
            continue;
        }

        panic!("send() failed: {e:?}");
    }

    debug!("written {write}");

    let mut wt_conn = None;
    let mut wt_session_established = false;
    let mut wt_data_sent = false;
    let mut wt_data_received = false;

    let send_data = b"Hello, WebTransport!";

    loop {
        poll.poll(&mut events, conn.timeout()).unwrap();

        // Read incoming UDP packets from the socket and feed them to quiche,
        // until there are no more packets to read.
        'read: loop {
            if events.is_empty() {
                debug!("timed out");

                conn.on_timeout();

                break 'read;
            }

            let (len, from) = match socket.recv_from(&mut buf) {
                Ok(v) => v,

                Err(e) => {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        debug!("recv() would block");
                        break 'read;
                    }

                    panic!("recv() failed: {e:?}");
                },
            };

            debug!("got {len} bytes");

            let recv_info = quiche::RecvInfo {
                to: socket.local_addr().unwrap(),
                from,
            };

            // Process potentially coalesced packets.
            let read = match conn.recv(&mut buf[..len], recv_info) {
                Ok(v) => v,

                Err(e) => {
                    error!("recv failed: {e:?}");
                    continue 'read;
                },
            };

            debug!("processed {read} bytes");
        }

        debug!("done reading");

        if conn.is_closed() {
            info!("connection closed, {:?}", conn.stats());
            break;
        }

        // Create a new WebTransport connection once the QUIC handshake
        // completes.
        if (conn.is_in_early_data() || conn.is_established()) && wt_conn.is_none()
        {
            debug!(
                "{} QUIC handshake completed, now creating WebTransport",
                conn.trace_id()
            );

            match quiche::webtransport::Connection::with_transport(
                &mut conn, &h3_config,
            ) {
                Ok(wt) => {
                    wt_conn = Some(wt);
                },

                Err(e) => {
                    error!("failed to create WebTransport connection: {e}");
                    break;
                },
            };
        }

        if let Some(wt_conn) = &mut wt_conn {
            // Establish the WebTransport session via extended CONNECT.
            if !wt_session_established {
                info!("sending WebTransport CONNECT");

                let authority = url.host_str().unwrap().as_bytes();
                let path = url.path().as_bytes();
                let origin = url.host_str().unwrap().as_bytes();

                match wt_conn.connect(&mut conn, authority, path, origin) {
                    Ok(stream_id) => {
                        info!(
                            "WebTransport CONNECT sent on stream {}",
                            stream_id
                        );
                        wt_session_established = true;
                    },

                    Err(e) => {
                        error!("failed to send CONNECT: {e}");
                        break;
                    },
                }
            }

            // Open a bidirectional stream and send data.
            if wt_session_established && !wt_data_sent {
                match wt_conn.open_bi_stream(&mut conn) {
                    Ok(stream_id) => {
                        info!("opened bidirectional stream {}", stream_id);

                        match wt_conn.stream_write_data(
                            &mut conn, stream_id, send_data, true,
                        ) {
                            Ok(n) => {
                                info!("sent {} bytes on stream {}", n, stream_id);
                                wt_data_sent = true;
                            },

                            Err(e) => {
                                error!("failed to write data: {e}");
                                break;
                            },
                        }
                    },

                    Err(e) => {
                        error!("failed to open bi stream: {e}");
                        break;
                    },
                }
            }

            // Process WebTransport events.
            loop {
                match wt_conn.poll(&mut conn) {
                    Ok((stream_id, quiche::webtransport::Event::H3(e))) => {
                        info!("H3 event on stream {}: {:?}", stream_id, e,);
                    },

                    Ok((
                        _stream_id,
                        quiche::webtransport::Event::SessionRequest { headers },
                    )) => {
                        info!(
                            "received session request: {:?}",
                            hdrs_to_strings(&headers),
                        );
                    },

                    Ok((
                        stream_id,
                        quiche::webtransport::Event::Stream { session_id },
                    )) => {
                        info!(
                            "new WebTransport stream {}, session {}",
                            stream_id, session_id,
                        );
                    },

                    Ok((stream_id, quiche::webtransport::Event::Data)) => {
                        info!("data available on stream {}", stream_id);

                        let mut rbuf = [0; 1024];
                        let read = match wt_conn
                            .stream_recv_data(&mut conn, stream_id, &mut rbuf)
                        {
                            Ok(n) => n,

                            Err(e) => {
                                error!(
                                    "failed to read data on stream {}: {:?}",
                                    stream_id, e,
                                );
                                break;
                            },
                        };

                        info!("{}", String::from_utf8_lossy(&rbuf[..read]),);

                        wt_data_received = true;

                        wt_conn.close(&mut conn).ok();
                    },

                    Err(quiche::h3::Error::Done) => {
                        break;
                    },

                    Err(e) => {
                        error!("WebTransport poll failed: {e:?}");
                        break;
                    },
                }
            }
        }

        // Generate outgoing QUIC packets and send them on the UDP socket,
        // until quiche reports that there are no more packets to be sent.
        loop {
            let (write, send_info) = match conn.send(&mut out) {
                Ok(v) => v,

                Err(quiche::Error::Done) => {
                    debug!("done writing");
                    break;
                },

                Err(e) => {
                    error!("send failed: {e:?}");

                    conn.close(false, 0x1, b"fail").ok();
                    break;
                },
            };

            if let Err(e) = socket.send_to(&out[..write], send_info.to) {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    debug!("send() would block");
                    break;
                }

                panic!("send() failed: {e:?}");
            }

            debug!("written {write}");
        }

        if conn.is_closed() {
            info!("connection closed, {:?}", conn.stats());
            break;
        }

        // Close after we've received the echo.
        if wt_data_received {
            info!("echo received, closing connection");
            conn.close(true, 0x0, b"done").ok();
        }
    }
}

fn hex_dump(buf: &[u8]) -> String {
    let vec: Vec<String> = buf.iter().map(|b| format!("{b:02x}")).collect();

    vec.join("")
}

pub fn hdrs_to_strings(hdrs: &[quiche::h3::Header]) -> Vec<(String, String)> {
    hdrs.iter()
        .map(|h| {
            let name = String::from_utf8_lossy(h.name()).to_string();
            let value = String::from_utf8_lossy(h.value()).to_string();

            (name, value)
        })
        .collect()
}

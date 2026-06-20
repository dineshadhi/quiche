//! WebTransport over HTTP/3.
//!
//! Provides a [`Connection`] for managing WebTransport sessions established
//! via HTTP/3 CONNECT, and an [`Event`] enum for WebTransport-related events.

mod connection;

pub use connection::Connection;

/// WebTransport events returned by [`Connection::poll()`].
#[derive(Debug, PartialEq)]
pub enum Event {
    /// An HTTP/3 event that is not specific to any WebTransport session.
    /// Contains the original [`h3::Event`].
    H3(crate::h3::Event),

    /// An incoming CONNECT request for a new WebTransport session.
    /// Call [`Connection::accept()`] on the stream to establish the session.
    SessionRequest {
        /// The request headers.
        headers: Vec<crate::h3::Header>,
    },

    /// A new WebTransport stream was opened within an established session.
    Stream {
        /// The session ID the stream belongs to.
        session_id: u64,
    },

    /// Data is available for reading on a WebTransport stream.
    /// Use [`crate::Connection::stream_recv()`] to read.
    Data,
}

#[doc(hidden)]
#[cfg(any(test, feature = "internal"))]
pub mod testing {
    use crate::buffers::BufFactory;
    use crate::h3;
    use crate::test_utils;
    use crate::DefaultBufFactory;

    /// An in-memory WebTransport test helper.
    ///
    /// Holds a [`test_utils::Pipe`], plus a client and server
    /// [`super::Connection`].
    pub struct Session<F = DefaultBufFactory>
    where
        F: BufFactory,
    {
        /// The in-memory QUIC transport.
        pub pipe: test_utils::Pipe<F>,

        /// The WebTransport connection acting as the client.
        pub client: super::Connection,

        /// The WebTransport connection acting as the server.
        pub server: super::Connection,
    }

    impl Session {
        pub fn new() -> h3::Result<Session> {
            Session::<DefaultBufFactory>::new_with_buf()
        }

        pub fn with_configs(
            config: &mut crate::Config, h3_config: &h3::Config,
        ) -> h3::Result<Session> {
            Session::<DefaultBufFactory>::with_configs_and_buf(config, h3_config)
        }

        pub fn default_configs() -> h3::Result<(crate::Config, h3::Config)> {
            let mut config = crate::Config::new(crate::PROTOCOL_VERSION)?;
            config.load_cert_chain_from_pem_file("examples/cert.crt")?;
            config.load_priv_key_from_pem_file("examples/cert.key")?;
            config.set_application_protos(h3::APPLICATION_PROTOCOL)?;
            config.set_initial_max_data(10_000_000);
            config.set_initial_max_stream_data_bidi_local(1_000_000);
            config.set_initial_max_stream_data_bidi_remote(1_000_000);
            config.set_initial_max_stream_data_uni(1_000_000);
            config.set_initial_max_streams_bidi(100);
            config.set_initial_max_streams_uni(100);
            config.verify_peer(false);
            config.enable_dgram(true, 100, 100);
            config.set_ack_delay_exponent(8);

            let mut h3_config = h3::Config::new()?;
            h3_config.enable_extended_connect(true);
            h3_config.enable_webtransport_draft02(true);

            Ok((config, h3_config))
        }
    }

    impl<F: BufFactory> Session<F> {
        pub fn new_with_buf() -> h3::Result<Session<F>> {
            let (mut config, h3_config) = Session::default_configs()?;
            Session::<F>::with_configs_and_buf(&mut config, &h3_config)
        }

        pub fn with_configs_and_buf(
            config: &mut crate::Config, h3_config: &h3::Config,
        ) -> h3::Result<Session<F>> {
            let mut pipe = test_utils::Pipe::with_config_and_buf(config)?;
            pipe.handshake()?;

            let client =
                super::Connection::with_transport(&mut pipe.client, h3_config)?;
            let server =
                super::Connection::with_transport(&mut pipe.server, h3_config)?;

            pipe.advance()?;

            let mut c = client;
            let mut s = server;
            while c.poll(&mut pipe.client).is_ok() {}
            while s.poll(&mut pipe.server).is_ok() {}

            Ok(Session {
                pipe,
                client: c,
                server: s,
            })
        }

        pub fn with_separate_configs(
            config: &mut crate::Config, client_h3_config: &h3::Config,
            server_h3_config: &h3::Config,
        ) -> h3::Result<Session<F>> {
            let mut pipe = test_utils::Pipe::with_config_and_buf(config)?;
            pipe.handshake()?;

            let client = super::Connection::with_transport(
                &mut pipe.client,
                client_h3_config,
            )?;
            let server = super::Connection::with_transport(
                &mut pipe.server,
                server_h3_config,
            )?;

            pipe.advance()?;

            let mut c = client;
            let mut s = server;
            while c.poll(&mut pipe.client).is_ok() {}
            while s.poll(&mut pipe.server).is_ok() {}

            Ok(Session {
                pipe,
                client: c,
                server: s,
            })
        }

        pub fn advance(&mut self) -> crate::Result<()> {
            self.pipe.advance()
        }

        pub fn poll_client(&mut self) -> h3::Result<(u64, super::Event)> {
            self.client.poll(&mut self.pipe.client)
        }

        pub fn poll_server(&mut self) -> h3::Result<(u64, super::Event)> {
            self.server.poll(&mut self.pipe.server)
        }

        pub fn client_connect(
            &mut self, authority: &[u8], path: &[u8], origin: &[u8],
        ) -> h3::Result<u64> {
            let stream_id = self.client.connect(
                &mut self.pipe.client,
                authority,
                path,
                origin,
            )?;
            self.advance().ok();
            Ok(stream_id)
        }

        pub fn server_accept(&mut self, stream_id: u64) -> h3::Result<()> {
            self.server.accept(&mut self.pipe.server, stream_id)?;
            self.advance().ok();
            Ok(())
        }

        pub fn server_accept_deferred(
            &mut self, stream_id: u64,
        ) -> h3::Result<()> {
            let headers = vec![h3::Header::new(b":status", b"200")];
            self.server.send_response(
                &mut self.pipe.server,
                stream_id,
                &headers,
                false,
            )?;
            self.advance().ok();
            self.server.set_session_id(stream_id);
            Ok(())
        }

        pub fn open_uni_client(&mut self) -> h3::Result<u64> {
            let id = self.client.open_uni_stream(&mut self.pipe.client)?;
            self.advance().ok();
            Ok(id)
        }

        pub fn open_uni_server(&mut self) -> h3::Result<u64> {
            let id = self.server.open_uni_stream(&mut self.pipe.server)?;
            self.advance().ok();
            Ok(id)
        }

        pub fn open_bi_client(&mut self) -> h3::Result<u64> {
            let id = self.client.open_bi_stream(&mut self.pipe.client)?;
            self.advance().ok();
            Ok(id)
        }

        pub fn open_bi_server(&mut self) -> h3::Result<u64> {
            let id = self.server.open_bi_stream(&mut self.pipe.server)?;
            self.advance().ok();
            Ok(id)
        }

        pub fn send_data_client(
            &mut self, stream_id: u64, data: &[u8], fin: bool,
        ) -> h3::Result<usize> {
            self.client.stream_write_data(
                &mut self.pipe.client,
                stream_id,
                data,
                fin,
            )
        }

        pub fn send_data_server(
            &mut self, stream_id: u64, data: &[u8], fin: bool,
        ) -> h3::Result<usize> {
            self.server.stream_write_data(
                &mut self.pipe.server,
                stream_id,
                data,
                fin,
            )
        }

        pub fn recv_data_client(
            &mut self, stream_id: u64, buf: &mut [u8],
        ) -> h3::Result<usize> {
            self.client
                .stream_recv_data(&mut self.pipe.client, stream_id, buf)
        }

        pub fn recv_data_server(
            &mut self, stream_id: u64, buf: &mut [u8],
        ) -> h3::Result<usize> {
            self.server
                .stream_recv_data(&mut self.pipe.server, stream_id, buf)
        }

        pub fn close_session_client(&mut self) -> h3::Result<()> {
            self.client.close(&mut self.pipe.client)?;
            self.advance().ok();
            Ok(())
        }

        pub fn close_session_server(&mut self) -> h3::Result<()> {
            self.server.close(&mut self.pipe.server)?;
            self.advance().ok();
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use crate::h3;
    use crate::h3::NameValue;

    /// Client sends CONNECT, server accepts, both sides drain cleanly.
    #[test]
    fn wt_connect_accept() {
        let mut s = Session::new().unwrap();

        let stream_id =
            s.client_connect(b"localhost", b"/", b"localhost").unwrap();

        let (sid, ev) = s.poll_server().unwrap();
        assert_eq!(sid, stream_id);
        match ev {
            super::Event::SessionRequest { .. } => {},
            _ => panic!("expected SessionRequest"),
        }

        s.server_accept(stream_id).unwrap();

        let (sid, ev) = s.poll_client().unwrap();
        assert_eq!(sid, stream_id);
        match ev {
            super::Event::H3(h3::Event::Headers { .. }) => {},
            _ => panic!("expected H3(Headers)"),
        }

        assert_eq!(s.poll_client(), Err(h3::Error::Done));
        assert_eq!(s.poll_server(), Err(h3::Error::Done));
    }

    /// Server sends 200 before setting session_id, then opens WT uni stream.
    #[test]
    fn wt_connect_deferred_accept() {
        let mut s = Session::new().unwrap();

        let stream_id =
            s.client_connect(b"localhost", b"/", b"localhost").unwrap();

        let (sid, _ev) = s.poll_server().unwrap();
        assert_eq!(sid, stream_id);

        s.server_accept_deferred(stream_id).unwrap();

        let (sid, ev) = s.poll_client().unwrap();
        assert_eq!(sid, stream_id);
        match ev {
            super::Event::H3(h3::Event::Headers { .. }) => {},
            _ => panic!("expected H3(Headers)"),
        }

        let uni = s.open_uni_client().unwrap();
        assert!(uni > 0);

        assert_eq!(s.poll_client(), Err(h3::Error::Done));

        // Server receives a Stream event for the new WebTransport uni stream.
        let (sid, ev) = s.poll_server().unwrap();
        assert_eq!(sid, uni);
        assert!(matches!(ev, super::Event::Stream { .. }));

        assert_eq!(s.poll_client(), Err(h3::Error::Done));
        assert_eq!(s.poll_server(), Err(h3::Error::Done));
    }

    /// Client sends data on a WT uni stream, server receives Stream + Data.
    #[test]
    fn wt_uni_stream() {
        let mut s = Session::new().unwrap();

        let session_id =
            s.client_connect(b"localhost", b"/", b"localhost").unwrap();
        let (sid, _ev) = s.poll_server().unwrap();
        assert_eq!(sid, session_id);
        s.server_accept(session_id).unwrap();
        let (sid, _ev) = s.poll_client().unwrap();
        assert_eq!(sid, session_id);

        let stream_id = s.open_uni_client().unwrap();
        let data = b"hello uni";
        s.send_data_client(stream_id, data, true).unwrap();
        s.advance().unwrap();

        let (sid, ev) = s.poll_server().unwrap();
        assert_eq!(sid, stream_id);
        match ev {
            super::Event::Stream { session_id: sid } => {
                assert_eq!(sid, session_id);
            },
            _ => panic!("expected Stream event"),
        }

        let (sid, ev) = s.poll_server().unwrap();
        assert_eq!(sid, stream_id);
        assert!(matches!(ev, super::Event::Data));

        let mut buf = [0; 1024];
        let n = s.recv_data_server(stream_id, &mut buf).unwrap();
        assert_eq!(&buf[..n], data);

        assert_eq!(s.poll_client(), Err(h3::Error::Done));
        assert_eq!(s.poll_server(), Err(h3::Error::Done));
    }

    /// Bidirectional WT stream: client sends, server echoes back.
    #[test]
    fn wt_bi_stream_echo() {
        let mut s = Session::new().unwrap();

        let session_id =
            s.client_connect(b"localhost", b"/", b"localhost").unwrap();
        let (sid, _ev) = s.poll_server().unwrap();
        assert_eq!(sid, session_id);
        s.server_accept(session_id).unwrap();
        let (sid, _ev) = s.poll_client().unwrap();
        assert_eq!(sid, session_id);

        let stream_id = s.open_bi_client().unwrap();
        let data = b"ping";
        s.send_data_client(stream_id, data, true).unwrap();
        s.advance().unwrap();

        let (sid, ev) = s.poll_server().unwrap();
        assert_eq!(sid, stream_id);
        assert!(matches!(ev, super::Event::Stream { .. }));

        let (sid, ev) = s.poll_server().unwrap();
        assert_eq!(sid, stream_id);
        assert!(matches!(ev, super::Event::Data));

        let mut buf = [0; 1024];
        let n = s.recv_data_server(stream_id, &mut buf).unwrap();
        assert_eq!(&buf[..n], data);

        s.send_data_server(stream_id, data, true).unwrap();
        s.advance().unwrap();

        let (sid, ev) = s.poll_client().unwrap();
        assert_eq!(sid, stream_id);
        assert!(matches!(ev, super::Event::Data));

        let n = s.recv_data_client(stream_id, &mut buf).unwrap();
        assert_eq!(&buf[..n], data);

        assert_eq!(s.poll_client(), Err(h3::Error::Done));
        assert_eq!(s.poll_server(), Err(h3::Error::Done));
    }

    /// Multiple uni + bi WT streams are opened and deliver data to server.
    #[test]
    fn wt_multiple_streams() {
        let mut s = Session::new().unwrap();

        let session_id =
            s.client_connect(b"localhost", b"/", b"localhost").unwrap();
        let (sid, _ev) = s.poll_server().unwrap();
        assert_eq!(sid, session_id);
        s.server_accept(session_id).unwrap();
        let (sid, _ev) = s.poll_client().unwrap();
        assert_eq!(sid, session_id);

        let uni1 = s.open_uni_client().unwrap();
        let uni2 = s.open_uni_client().unwrap();
        let uni3 = s.open_uni_client().unwrap();
        let bi1 = s.open_bi_client().unwrap();
        let bi2 = s.open_bi_client().unwrap();

        s.send_data_client(uni1, b"u1", true).unwrap();
        s.send_data_client(uni2, b"u2", true).unwrap();
        s.send_data_client(uni3, b"u3", true).unwrap();
        s.send_data_client(bi1, b"b1", true).unwrap();
        s.send_data_client(bi2, b"b2", true).unwrap();
        s.advance().unwrap();

        let mut stream_events = Vec::new();
        let mut data_sids = Vec::new();
        while let Ok((sid, ev)) = s.poll_server() {
            match ev {
                super::Event::Stream { .. } => stream_events.push(sid),
                super::Event::Data => data_sids.push(sid),
                _ => {},
            }
        }

        assert_eq!(stream_events.len(), 5);
        assert_eq!(data_sids.len(), 5);

        let expected = [
            (uni1, b"u1"),
            (uni2, b"u2"),
            (uni3, b"u3"),
            (bi1, b"b1"),
            (bi2, b"b2"),
        ];
        let mut buf = [0; 1024];
        for (stream_id, want) in &expected {
            let n = s.recv_data_server(*stream_id, &mut buf).unwrap();
            assert_eq!(&buf[..n], *want);
        }
    }

    /// Client closes the WT session, server receives Finished on CONNECT.
    #[test]
    fn wt_session_close() {
        let mut s = Session::new().unwrap();

        let stream_id =
            s.client_connect(b"localhost", b"/", b"localhost").unwrap();
        let (sid, _ev) = s.poll_server().unwrap();
        assert_eq!(sid, stream_id);
        s.server_accept(stream_id).unwrap();
        let (sid, _ev) = s.poll_client().unwrap();
        assert_eq!(sid, stream_id);

        s.close_session_client().unwrap();

        let (sid, ev) = s.poll_server().unwrap();
        assert_eq!(sid, stream_id);
        match ev {
            super::Event::H3(h3::Event::Finished) => {},
            _ => panic!("expected H3(Finished)"),
        }

        assert_eq!(s.poll_client(), Err(h3::Error::Done));
        assert_eq!(s.poll_server(), Err(h3::Error::Done));
    }

    /// open_uni_stream and open_bi_stream fail when no session is established.
    #[test]
    fn wt_operations_without_session() {
        let mut s = Session::new().unwrap();

        assert_eq!(
            s.client.open_uni_stream(&mut s.pipe.client),
            Err(h3::Error::InternalError),
        );
        assert_eq!(
            s.client.open_bi_stream(&mut s.pipe.client),
            Err(h3::Error::InternalError),
        );
    }

    /// Server opens a WT uni stream, client receives Stream event.
    #[test]
    fn wt_peer_initiated_stream() {
        let mut s = Session::new().unwrap();

        let session_id =
            s.client_connect(b"localhost", b"/", b"localhost").unwrap();
        let (sid, _ev) = s.poll_server().unwrap();
        assert_eq!(sid, session_id);
        s.server_accept(session_id).unwrap();
        let (sid, _ev) = s.poll_client().unwrap();
        assert_eq!(sid, session_id);

        let server_stream = s.open_uni_server().unwrap();

        let (sid, ev) = s.poll_client().unwrap();
        assert_eq!(sid, server_stream);
        match ev {
            super::Event::Stream { session_id: sid } => {
                assert_eq!(sid, session_id);
            },
            _ => panic!("expected Stream event"),
        }

        assert_eq!(s.poll_client(), Err(h3::Error::Done));
        assert_eq!(s.poll_server(), Err(h3::Error::Done));
    }

    /// HTTP/3 request and WT uni stream coexist on the same connection.
    #[test]
    fn wt_h3_interop() {
        let mut s = Session::new().unwrap();

        // Establish a WebTransport session.
        let session_id =
            s.client_connect(b"localhost", b"/", b"localhost").unwrap();
        let (sid, ev) = s.poll_server().unwrap();
        assert_eq!(sid, session_id);
        assert!(matches!(ev, super::Event::SessionRequest { .. }));
        s.server_accept(session_id).unwrap();
        let (sid, ev) = s.poll_client().unwrap();
        assert_eq!(sid, session_id);
        assert!(matches!(ev, super::Event::H3(h3::Event::Headers { .. })));

        // Send a regular HTTP GET request via the underlying h3 connection.
        let req_headers = vec![
            h3::Header::new(b":method", b"GET"),
            h3::Header::new(b":scheme", b"https"),
            h3::Header::new(b":authority", b"localhost"),
            h3::Header::new(b":path", b"/test"),
        ];
        let req_stream_id = s
            .client
            .h3_conn
            .send_request(&mut s.pipe.client, &req_headers, true)
            .unwrap();

        // Also open a WebTransport uni stream.
        let wt_stream = s.open_uni_client().unwrap();

        // Server should get the HTTP request and the WT stream (any order).
        let mut h3_ok = false;
        let mut wt_ok = false;
        while let Ok((sid, ev)) = s.poll_server() {
            match ev {
                super::Event::H3(h3::Event::Headers { .. }) => {
                    assert_eq!(sid, req_stream_id);
                    h3_ok = true;
                },
                super::Event::Stream { .. } => {
                    assert_eq!(sid, wt_stream);
                    wt_ok = true;
                },
                _ => {},
            }
        }
        assert!(h3_ok);
        assert!(wt_ok);

        assert_eq!(s.poll_client(), Err(h3::Error::Done));
        assert_eq!(s.poll_server(), Err(h3::Error::Done));
    }

    /// Stream ID is not advanced when open_uni_stream fails (StreamLimit).
    #[test]
    fn wt_stream_id_not_consumed_on_fail() {
        let mut config = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        config
            .load_cert_chain_from_pem_file("examples/cert.crt")
            .unwrap();
        config
            .load_priv_key_from_pem_file("examples/cert.key")
            .unwrap();
        config
            .set_application_protos(h3::APPLICATION_PROTOCOL)
            .unwrap();
        config.set_initial_max_data(10_000_000);
        config.set_initial_max_stream_data_bidi_local(1_000_000);
        config.set_initial_max_stream_data_bidi_remote(1_000_000);
        config.set_initial_max_stream_data_uni(1_000_000);
        config.set_initial_max_streams_bidi(100);
        config.set_initial_max_streams_uni(3);
        config.verify_peer(false);
        config.enable_dgram(true, 100, 100);
        config.set_ack_delay_exponent(8);
        config.grease(false);

        let mut h3_config = h3::Config::new().unwrap();
        h3_config.enable_extended_connect(true);
        h3_config.enable_webtransport_draft02(true);

        let mut s = Session::with_configs(&mut config, &h3_config).unwrap();

        let stream_id =
            s.client_connect(b"localhost", b"/", b"localhost").unwrap();
        let (sid, _ev) = s.poll_server().unwrap();
        assert_eq!(sid, stream_id);
        s.server_accept(stream_id).unwrap();
        let (sid, ev) = s.poll_client().unwrap();
        assert_eq!(sid, stream_id);
        assert!(matches!(ev, super::Event::H3(h3::Event::Headers { .. })));

        // The first 3 uni streams are consumed by control, QPACK encoder, and
        // QPACK decoder. With max_streams_uni=3 and grease disabled, the next
        // WT uni stream should fail with StreamLimit.
        let before = s.client.h3_conn.next_uni_stream_id();
        let result = s.client.open_uni_stream(&mut s.pipe.client);
        assert!(result.is_err());
        let after = s.client.h3_conn.next_uni_stream_id();
        assert_eq!(before, after);
    }

    fn base_quic_config() -> crate::Config {
        let mut config = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        config
            .load_cert_chain_from_pem_file("examples/cert.crt")
            .unwrap();
        config
            .load_priv_key_from_pem_file("examples/cert.key")
            .unwrap();
        config
            .set_application_protos(h3::APPLICATION_PROTOCOL)
            .unwrap();
        config.set_initial_max_data(10_000_000);
        config.set_initial_max_stream_data_bidi_local(1_000_000);
        config.set_initial_max_stream_data_bidi_remote(1_000_000);
        config.set_initial_max_stream_data_uni(1_000_000);
        config.set_initial_max_streams_bidi(100);
        config.set_initial_max_streams_uni(100);
        config.verify_peer(false);
        config.enable_dgram(true, 100, 100);
        config.set_ack_delay_exponent(8);
        config.grease(false);
        config
    }

    /// Server rejects WebTransport session when client does not advertise
    /// extended CONNECT in SETTINGS.
    #[test]
    fn wt_accept_rejects_without_extended_connect() {
        // Client has no extended connect or WT support.
        let client_h3 = h3::Config::new().unwrap();

        // Server has both enabled.
        let mut server_h3 = h3::Config::new().unwrap();
        server_h3.enable_extended_connect(true);
        server_h3.enable_webtransport_draft02(true);

        let mut config = base_quic_config();
        let mut s: Session =
            Session::with_separate_configs(&mut config, &client_h3, &server_h3)
                .unwrap();

        // Client sends CONNECT with :protocol: webtransport.
        let stream_id =
            s.client_connect(b"localhost", b"/", b"localhost").unwrap();

        // Server receives the SessionRequest.
        let (sid, ev) = s.poll_server().unwrap();
        assert_eq!(sid, stream_id);
        assert!(matches!(ev, super::Event::SessionRequest { .. }));

        // Server rejects — client didn't advertise extended connect.
        let result = s.server.accept(&mut s.pipe.server, stream_id);
        assert_eq!(result, Err(h3::Error::RequestRejected));
        assert_eq!(s.server.session_id(), None);

        // Client receives the 400 response.
        s.advance().unwrap();
        let (sid, ev) = s.poll_client().unwrap();
        assert_eq!(sid, stream_id);
        match ev {
            super::Event::H3(h3::Event::Headers { list, .. }) => {
                let status = list
                    .iter()
                    .find(|h| h.name() == b":status")
                    .map(|h| h.value())
                    .unwrap();
                assert_eq!(status, b"400");
            },
            _ => panic!("expected H3(Headers)"),
        }

        // Client also gets Finished on the closed CONNECT stream.
        let (sid, ev) = s.poll_client().unwrap();
        assert_eq!(sid, stream_id);
        assert!(matches!(ev, super::Event::H3(h3::Event::Finished)));

        assert_eq!(s.poll_client(), Err(h3::Error::Done));
        assert_eq!(s.poll_server(), Err(h3::Error::Done));
    }

    /// Server rejects WebTransport session when client does not advertise
    /// WebTransport draft-02 in SETTINGS.
    #[test]
    fn wt_accept_rejects_without_wt_draft02() {
        // Client has extended connect but NOT webtransport draft-02.
        let mut client_h3 = h3::Config::new().unwrap();
        client_h3.enable_extended_connect(true);

        // Server has both enabled.
        let mut server_h3 = h3::Config::new().unwrap();
        server_h3.enable_extended_connect(true);
        server_h3.enable_webtransport_draft02(true);

        let mut config = base_quic_config();
        let mut s: Session =
            Session::with_separate_configs(&mut config, &client_h3, &server_h3)
                .unwrap();

        // Client sends CONNECT with :protocol: webtransport.
        let stream_id =
            s.client_connect(b"localhost", b"/", b"localhost").unwrap();

        // Server receives the SessionRequest.
        let (sid, ev) = s.poll_server().unwrap();
        assert_eq!(sid, stream_id);
        assert!(matches!(ev, super::Event::SessionRequest { .. }));

        // Server rejects — client didn't advertise WT draft-02.
        let result = s.server.accept(&mut s.pipe.server, stream_id);
        assert_eq!(result, Err(h3::Error::RequestRejected));
        assert_eq!(s.server.session_id(), None);

        // Client receives the 400 response.
        s.advance().unwrap();
        let (sid, ev) = s.poll_client().unwrap();
        assert_eq!(sid, stream_id);
        match ev {
            super::Event::H3(h3::Event::Headers { list, .. }) => {
                let status = list
                    .iter()
                    .find(|h| h.name() == b":status")
                    .map(|h| h.value())
                    .unwrap();
                assert_eq!(status, b"400");
            },
            _ => panic!("expected H3(Headers)"),
        }

        // Client also gets Finished on the closed CONNECT stream.
        let (sid, ev) = s.poll_client().unwrap();
        assert_eq!(sid, stream_id);
        assert!(matches!(ev, super::Event::H3(h3::Event::Finished)));

        assert_eq!(s.poll_client(), Err(h3::Error::Done));
        assert_eq!(s.poll_server(), Err(h3::Error::Done));
    }
}

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


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

use crate::buffers::BufFactory;
use crate::h3;

const WEBTRANSPORT_UNI_STREAM_TYPE: u64 = 0x54;
const WEBTRANSPORT_BI_STREAM_TYPE: u64 = 0x41;

/// A WebTransport session.
///
/// Wraps an HTTP/3 connection and provides WebTransport-specific event
/// polling and stream management. The underlying HTTP/3 connection is
/// owned by this struct, so all HTTP/3 operations go through it.
pub struct Connection {
    session_id: Option<u64>,
    pub(crate) h3_conn: h3::Connection,
}

impl Connection {
    /// Creates a new WebTransport connection, wrapping the given HTTP/3
    /// connection.
    ///
    /// `session_id` is `Some(stream_id)` when this represents an established
    /// session, or `None` for the initial poll wrapper.
    fn new(h3_conn: h3::Connection, session_id: Option<u64>) -> Self {
        Connection {
            session_id,
            h3_conn,
        }
    }

    /// Creates a new WebTransport connection using the given QUIC connection
    /// and HTTP/3 configuration.
    ///
    /// This is the main constructor — it creates the HTTP/3 connection
    /// internally and wraps it.
    pub fn with_transport<F: BufFactory>(
        conn: &mut crate::Connection<F>, config: &h3::Config,
    ) -> h3::Result<Self> {
        let h3_conn = h3::Connection::with_transport(conn, config)?;
        Ok(Connection::new(h3_conn, None))
    }

    /// Sends an extended CONNECT request to establish a WebTransport session.
    ///
    /// This is a client-side convenience that sends the CONNECT request with
    /// `:protocol: webtransport`. The caller must separately poll for the 2xx
    /// response.
    pub fn connect<F: BufFactory>(
        &mut self, conn: &mut crate::Connection<F>, authority: &[u8],
        path: &[u8], origin: &[u8],
    ) -> h3::Result<u64> {
        let headers = vec![
            h3::Header::new(b":method", b"CONNECT"),
            h3::Header::new(b":protocol", b"webtransport"),
            h3::Header::new(b":scheme", b"https"),
            h3::Header::new(b":authority", authority),
            h3::Header::new(b":path", path),
            h3::Header::new(b"origin", origin),
        ];

        let stream_id = self.h3_conn.send_request(conn, &headers, false)?;

        self.session_id = Some(stream_id);

        Ok(stream_id)
    }

    /// Accepts an incoming CONNECT request on the given stream, establishing
    /// a WebTransport session.
    ///
    /// Validates that the peer advertised WebTransport support in its
    /// SETTINGS frame (draft-02) before accepting.
    /// Returns [`RequestRejected`] if the peer did not advertise support.
    ///
    /// On success sends a 200 response to accept the session.
    pub fn accept<F: BufFactory>(
        &mut self, conn: &mut crate::Connection<F>, stream_id: u64,
    ) -> h3::Result<()> {
        // WebTransport draft-02 support implies extended CONNECT support, so
        // checking only the draft-02 setting is sufficient. Some peers (e.g.
        // Chrome) do not send SETTINGS_ENABLE_CONNECT_PROTOCOL separately.
        if !self.h3_conn.webtransport_draft02_enabled_by_peer() {
            let headers = vec![h3::Header::new(b":status", b"400")];
            self.h3_conn
                .send_response(conn, stream_id, &headers, true)?;
            return Err(h3::Error::RequestRejected);
        }

        let headers = vec![h3::Header::new(b":status", b"200")];
        self.h3_conn
            .send_response(conn, stream_id, &headers, false)?;

        self.session_id = Some(stream_id);

        Ok(())
    }

    /// Returns the stream ID of the CONNECT stream that established this
    /// session, or `None` if no session has been established yet.
    pub fn session_id(&self) -> Option<u64> {
        self.session_id
    }

    /// Sets the session ID for this connection.
    pub fn set_session_id(&mut self, id: u64) {
        self.session_id = Some(id);
    }

    /// Processes incoming events.
    ///
    /// Internally polls the HTTP/3 connection and returns
    /// [`Event`](crate::webtransport::Event) variants.
    pub fn poll<F: BufFactory>(
        &mut self, conn: &mut crate::Connection<F>,
    ) -> h3::Result<(u64, super::Event)> {
        use h3::NameValue;

        let (id, event) = self.h3_conn.poll(conn)?;
        match event {
            h3::Event::Headers { list, more_frames } => {
                let is_connect = list
                    .iter()
                    .any(|h| h.name() == b":method" && h.value() == b"CONNECT");
                let is_webtransport = list.iter().any(|h| {
                    h.name() == b":protocol" && h.value() == b"webtransport"
                });
                if is_connect && is_webtransport {
                    return Ok((id, super::Event::SessionRequest {
                        headers: list,
                    }));
                }

                Ok((
                    id,
                    super::Event::H3(h3::Event::Headers { list, more_frames }),
                ))
            },

            h3::Event::WebtransportStream { session_id } =>
                Ok((id, super::Event::Stream { session_id })),

            h3::Event::WebtransportData => Ok((id, super::Event::Data)),

            other => Ok((id, super::Event::H3(other))),
        }
    }

    /// Reads body data from a stream directly from the QUIC connection.
    pub fn stream_recv_data<F: BufFactory>(
        &mut self, conn: &mut crate::Connection<F>, stream_id: u64,
        out: &mut [u8],
    ) -> h3::Result<usize> {
        let (read, _fin) = conn.stream_recv(stream_id, out)?;
        Ok(read)
    }

    /// Sends response headers on a stream.
    pub fn send_response<F: BufFactory>(
        &mut self, conn: &mut crate::Connection<F>, stream_id: u64,
        headers: &[h3::Header], fin: bool,
    ) -> h3::Result<()> {
        self.h3_conn.send_response(conn, stream_id, headers, fin)
    }

    /// Writes body data directly to the QUIC connection.
    pub fn stream_write_data<F: BufFactory>(
        &mut self, conn: &mut crate::Connection<F>, stream_id: u64, body: &[u8],
        fin: bool,
    ) -> h3::Result<usize> {
        let written = conn.stream_send(stream_id, body, fin)?;
        Ok(written)
    }

    /// Opens a new unidirectional stream associated with this session.
    pub fn open_uni_stream<F: BufFactory>(
        &mut self, conn: &mut crate::Connection<F>,
    ) -> h3::Result<u64> {
        let session_id = self.session_id.ok_or(h3::Error::InternalError)?;
        let stream_id = self.h3_conn.next_uni_stream_id();

        let mut d = [0; 16];
        let mut b = octets::OctetsMut::with_slice(&mut d);

        b.put_varint(WEBTRANSPORT_UNI_STREAM_TYPE)?;
        b.put_varint(session_id)?;

        let off = b.off();
        conn.stream_send(stream_id, &d[..off], false)?;

        self.h3_conn.advance_next_uni_stream_id()?;
        self.h3_conn.register_webtransport_stream(stream_id);

        Ok(stream_id)
    }

    /// Opens a new bidirectional stream associated with this session.
    pub fn open_bi_stream<F: BufFactory>(
        &mut self, conn: &mut crate::Connection<F>,
    ) -> h3::Result<u64> {
        let session_id = self.session_id.ok_or(h3::Error::InternalError)?;
        let stream_id = self.h3_conn.next_bidi_stream_id();

        let mut d = [0; 16];
        let mut b = octets::OctetsMut::with_slice(&mut d);

        b.put_varint(WEBTRANSPORT_BI_STREAM_TYPE)?;
        b.put_varint(session_id)?;

        let off = b.off();
        conn.stream_send(stream_id, &d[..off], false)?;

        self.h3_conn.advance_next_bidi_stream_id()?;
        self.h3_conn.register_webtransport_stream(stream_id);

        Ok(stream_id)
    }

    /// Closes the WebTransport session by sending a FIN on the CONNECT stream.
    pub fn close<F: BufFactory>(
        &mut self, conn: &mut crate::Connection<F>,
    ) -> h3::Result<()> {
        let session_id = self.session_id.ok_or(h3::Error::InternalError)?;
        conn.stream_send(session_id, &[], true)?;
        Ok(())
    }
}

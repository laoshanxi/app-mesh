// tcp_transport.rs
//! TLS-enabled TCP transport with simple framed messaging protocol.
//!
//! Framing format:
//!     4 bytes magic (u32 big-endian)
//!   + 4 bytes length (u32 big-endian)
//!   + payload bytes

use byteorder::{BigEndian, WriteBytesExt};
use rustls::StreamOwned;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use crate::error::TransportError;
pub use crate::tls_config::{ClientCert, SslVerify};

/// Protocol constants
const TCP_MESSAGE_MAGIC: u32 = 0x07C707F8;
const TCP_MAX_BLOCK_SIZE: usize = 1024 * 1024 * 1024; // 1 GB

pub type Result<T> = std::result::Result<T, TransportError>;

/// TLS-wrapped, or plain for the TLS-at-gateway shape.
enum ServerStream {
    Tls(StreamOwned<rustls::ClientConnection, TcpStream>),
    Plain(TcpStream),
}

impl std::io::Read for ServerStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            ServerStream::Tls(stream) => stream.read(buf),
            ServerStream::Plain(stream) => stream.read(buf),
        }
    }
}

impl std::io::Write for ServerStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            ServerStream::Tls(stream) => stream.write(buf),
            ServerStream::Plain(stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            ServerStream::Tls(stream) => stream.flush(),
            ServerStream::Plain(stream) => stream.flush(),
        }
    }
}

impl ServerStream {
    fn set_read_timeout(&self, timeout: Option<std::time::Duration>) -> std::io::Result<()> {
        match self {
            ServerStream::Tls(stream) => stream.sock.set_read_timeout(timeout),
            ServerStream::Plain(stream) => stream.set_read_timeout(timeout),
        }
    }
}

/// Main TCP transport
pub struct TCPTransport {
    address: (String, u16),
    ssl_verify: SslVerify,
    ssl_client_cert: Option<ClientCert>,
    // True = plain TCP (TLS-at-gateway shape).
    plain: bool,
    socket: Option<ServerStream>,
    receive_buffer: Vec<u8>,
}

/// Result of one bounded receive attempt used by the background demuxer.
pub(crate) enum ReceivePoll {
    Message(Vec<u8>),
    Pending,
    Closed,
}

impl TCPTransport {
    pub fn new(
        address: (String, u16),
        ssl_verify: SslVerify,
        ssl_client_cert: Option<ClientCert>,
        plain: bool,
    ) -> Self {
        crate::tls_config::ensure_crypto_provider();
        Self { address, ssl_verify, ssl_client_cert, plain, socket: None, receive_buffer: Vec::new() }
    }

    /// Establishes a TCP+TLS connection, or a plain TCP connection when built
    /// with `plain_transport(true)`.
    pub fn connect(&mut self) -> Result<()> {
        let tcp = TcpStream::connect((&self.address.0[..], self.address.1))
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;
        tcp.set_nodelay(true).map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        if self.plain {
            self.socket = Some(ServerStream::Plain(tcp));
            self.receive_buffer.clear();
            return Ok(());
        }

        let tls_config = build_rustls_client_config(&self.ssl_verify, self.ssl_client_cert.as_ref())?;
        let server_name = rustls::pki_types::ServerName::try_from(self.address.0.clone())
            .map_err(|e| TransportError::ConfigError(format!("Invalid server name: {}", e)))?;
        let tls_conn = rustls::ClientConnection::new(Arc::new(tls_config), server_name)
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;
        let tls_stream = StreamOwned::new(tls_conn, tcp);

        self.socket = Some(ServerStream::Tls(tls_stream));
        self.receive_buffer.clear();
        Ok(())
    }

    pub fn close(&mut self) {
        if let Some(mut socket) = self.socket.take() {
            if let ServerStream::Tls(tls) = &mut socket {
                tls.conn.send_close_notify();
                let _ = tls.conn.complete_io(&mut tls.sock);
            }
        }
        self.receive_buffer.clear();
    }

    pub fn connected(&self) -> bool {
        self.socket.is_some()
    }

    /// Send a framed message
    pub fn send_message(&mut self, data: &[u8]) -> Result<()> {
        let stream = self.socket.as_mut().ok_or(TransportError::NotConnected)?;

        if data.len() > TCP_MAX_BLOCK_SIZE {
            return Err(TransportError::MessageTooLarge(data.len()));
        }

        let mut header = [0u8; 8];
        {
            let mut cursor = std::io::Cursor::new(&mut header[..]);
            cursor.write_u32::<BigEndian>(TCP_MESSAGE_MAGIC)?;
            cursor.write_u32::<BigEndian>(data.len() as u32)?;
        }

        stream.write_all(&header)?;
        if !data.is_empty() {
            stream.write_all(data)?;
        }
        stream.flush()?;
        Ok(())
    }

    /// Receive a framed message
    pub fn receive_message(&mut self) -> Result<Option<Vec<u8>>> {
        loop {
            if let Some(message) = self.take_buffered_message()? {
                return Ok(Some(message));
            }

            let stream = self.socket.as_mut().ok_or(TransportError::NotConnected)?;
            stream.set_read_timeout(None)?;
            let mut chunk = [0u8; 16 * 1024];
            match stream.read(&mut chunk) {
                Ok(0) => return Err(TransportError::ConnectionClosed),
                Ok(size) => self.receive_buffer.extend_from_slice(&chunk[..size]),
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Err(TransportError::ConnectionClosed),
                Err(e) => return Err(TransportError::ReceiveError(e.to_string())),
            }
        }
    }

    /// Attempt to receive one frame without holding the requester's transport
    /// mutex indefinitely. Partial plaintext is retained for the next poll.
    pub(crate) fn poll_message(&mut self, timeout: Duration) -> Result<ReceivePoll> {
        if let Some(message) = self.take_buffered_message()? {
            return Ok(ReceivePoll::Message(message));
        }

        let stream = self.socket.as_mut().ok_or(TransportError::NotConnected)?;
        stream.set_read_timeout(Some(timeout))?;
        let mut chunk = [0u8; 16 * 1024];
        let read_result = stream.read(&mut chunk);
        let reset_result = stream.set_read_timeout(None);
        if let Err(error) = reset_result {
            return Err(TransportError::IoError(error));
        }

        match read_result {
            Ok(0) => Ok(ReceivePoll::Closed),
            Ok(size) => {
                self.receive_buffer.extend_from_slice(&chunk[..size]);
                Ok(match self.take_buffered_message()? {
                    Some(message) => ReceivePoll::Message(message),
                    None => ReceivePoll::Pending,
                })
            }
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {
                Ok(ReceivePoll::Pending)
            }
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(ReceivePoll::Closed),
            Err(e) => Err(TransportError::ReceiveError(e.to_string())),
        }
    }

    fn take_buffered_message(&mut self) -> Result<Option<Vec<u8>>> {
        if self.receive_buffer.len() < 8 {
            return Ok(None);
        }

        let magic = u32::from_be_bytes(self.receive_buffer[0..4].try_into().unwrap());
        if magic != TCP_MESSAGE_MAGIC {
            return Err(TransportError::InvalidMagic(magic));
        }

        let len = u32::from_be_bytes(self.receive_buffer[4..8].try_into().unwrap()) as usize;
        if len > TCP_MAX_BLOCK_SIZE {
            return Err(TransportError::MessageTooLarge(len));
        }
        let frame_size = 8 + len;
        if self.receive_buffer.len() < frame_size {
            return Ok(None);
        }

        let message = self.receive_buffer[8..frame_size].to_vec();
        self.receive_buffer.drain(..frame_size);
        Ok(Some(message))
    }
}

impl Drop for TCPTransport {
    fn drop(&mut self) {
        self.close();
    }
}

fn build_rustls_client_config(ssl_verify: &SslVerify, ssl_client_cert: Option<&ClientCert>) -> Result<rustls::ClientConfig> {
    crate::tls_config::build_rustls_client_config(ssl_verify, ssl_client_cert).map_err(TransportError::ConfigError)
}

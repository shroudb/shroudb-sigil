use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::TcpStream;

use crate::error::ClientError;

/// TCP connection to a Sigil server speaking RESP3.
pub struct Connection {
    reader: BufReader<tokio::net::tcp::OwnedReadHalf>,
    writer: BufWriter<tokio::net::tcp::OwnedWriteHalf>,
}

impl Connection {
    /// Connect to a Sigil server.
    pub async fn connect(addr: &str) -> Result<Self, ClientError> {
        let stream = TcpStream::connect(addr).await?;
        let (r, w) = stream.into_split();
        Ok(Self {
            reader: BufReader::new(r),
            writer: BufWriter::new(w),
        })
    }

    /// Send a command and read the response.
    /// Commands are sent as RESP3 arrays of bulk strings.
    /// Responses are parsed as JSON (from bulk string) or errors (from simple error).
    pub async fn send_command(&mut self, args: &[&str]) -> Result<serde_json::Value, ClientError> {
        // Encode RESP3 array
        let mut buf = Vec::new();
        buf.extend_from_slice(format!("*{}\r\n", args.len()).as_bytes());
        for arg in args {
            buf.extend_from_slice(format!("${}\r\n", arg.len()).as_bytes());
            buf.extend_from_slice(arg.as_bytes());
            buf.extend_from_slice(b"\r\n");
        }

        self.writer.write_all(&buf).await?;
        self.writer.flush().await?;

        // Read response
        let mut line = String::new();
        self.reader.read_line(&mut line).await?;
        let line = line.trim_end();

        if line.is_empty() {
            return Err(ClientError::Protocol("empty response".into()));
        }

        match line.as_bytes()[0] {
            b'+' => {
                // Simple string — parse as JSON
                let body = &line[1..];
                serde_json::from_str(body).or_else(|_| Ok(serde_json::json!(body)))
            }
            b'-' => {
                // Error
                let msg = &line[1..];
                let msg = msg.strip_prefix("ERR ").unwrap_or(msg);
                Err(ClientError::Server(msg.to_string()))
            }
            b'$' => {
                // Bulk string — parse length, read body
                let len: usize = line[1..]
                    .parse()
                    .map_err(|_| ClientError::Protocol("invalid bulk length".into()))?;
                let mut body = vec![0u8; len];
                self.reader.read_exact(&mut body).await?;
                // Read trailing \r\n
                let mut crlf = [0u8; 2];
                self.reader.read_exact(&mut crlf).await?;

                let json: serde_json::Value = serde_json::from_slice(&body)
                    .map_err(|e| ClientError::Protocol(format!("invalid JSON: {e}")))?;
                Ok(json)
            }
            _ => Err(ClientError::Protocol(format!(
                "unexpected response type: {}",
                line
            ))),
        }
    }
}

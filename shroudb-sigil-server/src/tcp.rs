use std::sync::Arc;

use shroudb_protocol_wire::{Resp3Frame, reader::read_frame, writer::write_frame};
use shroudb_sigil_engine::engine::SigilEngine;
use shroudb_sigil_protocol::commands::parse_command;
use shroudb_sigil_protocol::dispatch::dispatch;
use shroudb_sigil_protocol::response::SigilResponse;
use shroudb_store::Store;
use tokio::io::BufReader;
use tokio::net::TcpListener;

/// Run the RESP3 TCP server. Dispatches commands to the SigilEngine.
pub async fn run_tcp<S: Store + 'static>(
    listener: TcpListener,
    engine: Arc<SigilEngine<S>>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    tracing::info!(
        addr = %listener.local_addr().unwrap(),
        "sigil TCP server listening"
    );

    loop {
        tokio::select! {
            biased;
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() { break; }
            }
            accept = listener.accept() => {
                match accept {
                    Ok((stream, addr)) => {
                        let engine = engine.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(stream, &engine).await {
                                tracing::debug!(%addr, error = %e, "connection closed");
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "TCP accept error");
                    }
                }
            }
        }
    }
}

async fn handle_connection<S: Store>(
    stream: tokio::net::TcpStream,
    engine: &SigilEngine<S>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);

    loop {
        let frame = match read_frame(&mut reader).await {
            Ok(Some(frame)) => frame,
            Ok(None) => return Ok(()), // clean disconnect
            Err(e) => {
                let err_frame = Resp3Frame::SimpleError(format!("ERR protocol: {e}"));
                let _ = write_frame(&mut writer, &err_frame).await;
                return Err(e.into());
            }
        };

        // Extract string arguments from the RESP3 array
        let args = match frame_to_args(&frame) {
            Ok(args) => args,
            Err(e) => {
                let err_frame = Resp3Frame::SimpleError(format!("ERR {e}"));
                write_frame(&mut writer, &err_frame).await?;
                continue;
            }
        };

        let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

        // Parse and dispatch
        let response = match parse_command(&arg_refs) {
            Ok(cmd) => dispatch(engine, cmd).await,
            Err(e) => SigilResponse::error(e),
        };

        // Serialize response to RESP3
        let resp_frame = response_to_frame(&response);
        write_frame(&mut writer, &resp_frame).await?;
    }
}

/// Extract string arguments from a RESP3 array frame.
fn frame_to_args(frame: &Resp3Frame) -> Result<Vec<String>, String> {
    match frame {
        Resp3Frame::Array(items) => {
            let mut args = Vec::with_capacity(items.len());
            for item in items {
                match item {
                    Resp3Frame::BulkString(bytes) => {
                        args.push(
                            String::from_utf8(bytes.clone())
                                .map_err(|_| "invalid UTF-8 in argument".to_string())?,
                        );
                    }
                    Resp3Frame::SimpleString(s) => {
                        args.push(s.clone());
                    }
                    _ => return Err("expected string arguments".into()),
                }
            }
            Ok(args)
        }
        _ => Err("expected array command".into()),
    }
}

/// Convert a SigilResponse to a RESP3 frame.
fn response_to_frame(response: &SigilResponse) -> Resp3Frame {
    match response {
        SigilResponse::Ok(data) => {
            // Return as a RESP3 map with key-value pairs
            let json = serde_json::to_string(data).unwrap_or_default();
            Resp3Frame::BulkString(json.into_bytes())
        }
        SigilResponse::Error(msg) => Resp3Frame::SimpleError(format!("ERR {msg}")),
    }
}

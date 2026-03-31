use std::sync::Arc;

use shroudb_acl::{AuthContext, TokenValidator};
use shroudb_protocol_wire::{Resp3Frame, reader::read_frame, writer::write_frame};
use shroudb_sigil_engine::engine::SigilEngine;
use shroudb_sigil_protocol::commands::{SigilCommand, parse_command};
use shroudb_sigil_protocol::dispatch::dispatch;
use shroudb_sigil_protocol::response::SigilResponse;
use shroudb_store::Store;
use tokio::io::BufReader;
use tokio::net::TcpListener;

/// Run the RESP3 TCP server. Dispatches commands to the SigilEngine.
///
/// `token_validator` is `None` when auth is disabled. When present,
/// connections must AUTH before any command except HEALTH and JWKS.
pub async fn run_tcp<S: Store + 'static>(
    listener: TcpListener,
    engine: Arc<SigilEngine<S>>,
    token_validator: Option<Arc<dyn TokenValidator>>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    tracing::info!(
        addr = %listener.local_addr().expect("listener bound"),
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
                        let validator = token_validator.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(stream, &engine, validator.as_deref()).await {
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
    token_validator: Option<&dyn TokenValidator>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);

    // Per-connection auth state. None = not yet authenticated.
    // When auth is disabled (no validator), we pass None to dispatch,
    // which skips ACL checks.
    let mut auth_context: Option<AuthContext> = None;
    let auth_required = token_validator.is_some();

    loop {
        let frame = match read_frame(&mut reader).await {
            Ok(Some(frame)) => frame,
            Ok(None) => return Ok(()),
            Err(e) => {
                let err_frame = Resp3Frame::SimpleError(format!("ERR protocol: {e}"));
                let _ = write_frame(&mut writer, &err_frame).await;
                return Err(e.into());
            }
        };

        let args = match frame_to_args(&frame) {
            Ok(args) => args,
            Err(e) => {
                let err_frame = Resp3Frame::SimpleError(format!("ERR {e}"));
                write_frame(&mut writer, &err_frame).await?;
                continue;
            }
        };

        let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

        let cmd = match parse_command(&arg_refs) {
            Ok(cmd) => cmd,
            Err(e) => {
                let resp_frame = response_to_frame(&SigilResponse::error(e));
                write_frame(&mut writer, &resp_frame).await?;
                continue;
            }
        };

        // Handle AUTH at the connection layer
        if let SigilCommand::Auth { ref token } = cmd {
            if let Some(validator) = token_validator {
                match validator.validate(token) {
                    Ok(tok) => {
                        auth_context = Some(tok.into_context());
                        let resp = response_to_frame(&SigilResponse::ok_simple());
                        write_frame(&mut writer, &resp).await?;
                    }
                    Err(e) => {
                        let resp =
                            response_to_frame(&SigilResponse::error(format!("auth failed: {e}")));
                        write_frame(&mut writer, &resp).await?;
                    }
                }
            } else {
                // Auth disabled — AUTH command is a no-op
                let resp = response_to_frame(&SigilResponse::ok_simple());
                write_frame(&mut writer, &resp).await?;
            }
            continue;
        }

        // If auth is required and this connection isn't authenticated,
        // only allow commands with AclRequirement::None
        if auth_required
            && auth_context.is_none()
            && cmd.acl_requirement() != shroudb_acl::AclRequirement::None
        {
            let resp = response_to_frame(&SigilResponse::error(
                "authentication required — send AUTH <token> first",
            ));
            write_frame(&mut writer, &resp).await?;
            continue;
        }

        // Dispatch with auth context
        let response = dispatch(engine, cmd, auth_context.as_ref()).await;
        let resp_frame = response_to_frame(&response);
        write_frame(&mut writer, &resp_frame).await?;
    }
}

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

fn response_to_frame(response: &SigilResponse) -> Resp3Frame {
    match response {
        SigilResponse::Ok(data) => {
            let json = serde_json::to_string(data).unwrap_or_default();
            Resp3Frame::BulkString(json.into_bytes())
        }
        SigilResponse::Error(msg) => Resp3Frame::SimpleError(format!("ERR {msg}")),
    }
}

use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::Arc;

use shroudb_acl::{AclRequirement, AuthContext, TokenValidator};
use shroudb_protocol_wire::Resp3Frame;
use shroudb_server_tcp::ServerProtocol;
use shroudb_sigil_engine::engine::SigilEngine;
use shroudb_sigil_protocol::commands::{SigilCommand, parse_command};
use shroudb_sigil_protocol::dispatch::dispatch;
use shroudb_sigil_protocol::response::SigilResponse;
use shroudb_store::Store;

pub struct SigilProtocol<S>(PhantomData<S>);

impl<S: Store + 'static> ServerProtocol for SigilProtocol<S> {
    type Command = SigilCommand;
    type Response = SigilResponse;
    type Engine = SigilEngine<S>;

    fn engine_name(&self) -> &str {
        "sigil"
    }

    fn parse_command(&self, args: &[&str]) -> Result<Self::Command, String> {
        parse_command(args)
    }

    fn auth_token(cmd: &Self::Command) -> Option<&str> {
        if let SigilCommand::Auth { token } = cmd {
            Some(token)
        } else {
            None
        }
    }

    fn acl_requirement(cmd: &Self::Command) -> AclRequirement {
        cmd.acl_requirement()
    }

    fn dispatch<'a>(
        &'a self,
        engine: &'a Self::Engine,
        cmd: Self::Command,
        auth: Option<&'a AuthContext>,
    ) -> Pin<Box<dyn Future<Output = Self::Response> + Send + 'a>> {
        Box::pin(dispatch(engine, cmd, auth))
    }

    fn response_to_frame(&self, response: &Self::Response) -> Resp3Frame {
        match response {
            SigilResponse::Ok(data) => {
                let json = serde_json::to_string(data).unwrap_or_default();
                Resp3Frame::BulkString(json.into_bytes())
            }
            SigilResponse::Error(msg) => Resp3Frame::SimpleError(format!("ERR {msg}")),
        }
    }

    fn error_response(&self, msg: String) -> Self::Response {
        SigilResponse::error(msg)
    }

    fn ok_response(&self) -> Self::Response {
        SigilResponse::ok_simple()
    }
}

pub async fn run_tcp<S: Store + 'static>(
    listener: tokio::net::TcpListener,
    engine: Arc<SigilEngine<S>>,
    token_validator: Option<Arc<dyn TokenValidator>>,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
    tls_acceptor: Option<tokio_rustls::TlsAcceptor>,
) {
    shroudb_server_tcp::run_tcp_tls(
        listener,
        engine,
        Arc::new(SigilProtocol::<S>(PhantomData)),
        token_validator,
        shutdown_rx,
        tls_acceptor,
    )
    .await;
}

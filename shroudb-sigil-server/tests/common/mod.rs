use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

/// Find a free TCP port.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn find_binary() -> Option<PathBuf> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let candidates = [
        PathBuf::from(manifest_dir).join("../target/debug/shroudb-sigil"),
        PathBuf::from(manifest_dir).join("target/debug/shroudb-sigil"),
    ];
    candidates.into_iter().find(|p| p.exists())
}

/// A running test server. Killed on drop.
pub struct TestServer {
    child: Child,
    pub tcp_addr: String,
    pub http_addr: String,
    _data_dir: tempfile::TempDir,
}

impl TestServer {
    pub async fn start() -> Option<Self> {
        let binary = find_binary()?;
        let tcp_port = free_port();
        let http_port = free_port();
        let tcp_addr = format!("127.0.0.1:{tcp_port}");
        let http_addr = format!("127.0.0.1:{http_port}");
        let data_dir = tempfile::tempdir().ok()?;

        let child = Command::new(&binary)
            .arg("--tcp-bind")
            .arg(&tcp_addr)
            .arg("--http-bind")
            .arg(&http_addr)
            .arg("--data-dir")
            .arg(data_dir.path())
            .arg("--log-level")
            .arg("warn")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .ok()?;

        let mut server = Self {
            child,
            tcp_addr: tcp_addr.clone(),
            http_addr: http_addr.clone(),
            _data_dir: data_dir,
        };

        // Wait for both TCP and HTTP to be ready
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            if tokio::time::Instant::now() > deadline {
                eprintln!("server failed to start");
                return None;
            }
            if let Some(status) = server.child.try_wait().ok().flatten() {
                eprintln!("server exited during startup: {status}");
                return None;
            }
            // Check HTTP health
            if let Ok(resp) = reqwest::get(format!("http://{http_addr}/sigil/health")).await
                && resp.status().is_success()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        Some(server)
    }

    pub fn http_url(&self, path: &str) -> String {
        format!("http://{}{}", self.http_addr, path)
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

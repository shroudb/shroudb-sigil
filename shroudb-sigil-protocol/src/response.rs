/// A Sigil command response, ready for RESP3 serialization.
#[derive(Debug)]
pub enum SigilResponse {
    /// Simple OK with optional data.
    Ok(serde_json::Value),
    /// Error response.
    Error(String),
}

impl SigilResponse {
    pub fn ok(data: serde_json::Value) -> Self {
        Self::Ok(data)
    }

    pub fn ok_simple() -> Self {
        Self::Ok(serde_json::json!({"status": "ok"}))
    }

    pub fn error(msg: impl Into<String>) -> Self {
        Self::Error(msg.into())
    }

    pub fn is_ok(&self) -> bool {
        matches!(self, Self::Ok(_))
    }

    /// Returns the JSON body as a string. Returns the error message for error
    /// responses.
    pub fn body(&self) -> String {
        match self {
            Self::Ok(v) => v.to_string(),
            Self::Error(e) => e.clone(),
        }
    }
}

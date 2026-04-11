//! Shared Axum HTTP router for the Sigil credential envelope engine.
//!
//! This crate provides the REST API surface for Sigil, reusable by both the
//! standalone `shroudb-sigil` server and `shroudb-moat` (unified gateway).
//!
//! # Usage
//!
//! ```rust,ignore
//! use shroudb_sigil_http::{router, HttpConfig};
//!
//! let router = router(engine, token_validator, HttpConfig::default());
//! ```

pub mod cors;
pub mod csrf;
pub mod rate_limit;
mod router;

pub use router::{HttpConfig, router};

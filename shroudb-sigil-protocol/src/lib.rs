//! RESP3 wire protocol for the Sigil credential envelope engine.
//!
//! Command parsing, dispatch, and response serialization. This is the
//! crate that Moat dispatches to — the standard engine integration path.

pub mod commands;
pub mod dispatch;
pub mod response;

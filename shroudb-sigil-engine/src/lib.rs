//! Store-backed credential envelope engine.
//!
//! This is the core Sigil engine — schema registry, credential lifecycle,
//! JWT management, session handling, and field-level crypto routing.
//! Consumes the ShrouDB Store trait for persistence.

pub mod capabilities;
pub mod credential;
pub mod engine;
pub mod jwt;
pub mod schema_registry;
pub mod session;
pub mod write_coordinator;

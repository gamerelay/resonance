//! A room-scoped TURN relay core (Resonance v0 §4), sans-I/O: packets and time in, packets out.
//! The rules are the Go relay's (gamerelay.io deploy/turn), rule for rule; the node binary owns
//! the sockets.

pub mod auth;
pub mod limiter;
pub mod server;
pub mod stun;

pub use server::{Config, Output, Server, Stats};

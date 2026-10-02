//! A room-scoped TURN relay core (Resonance v0 §4), sans-I/O: packets and time in, packets out.
//! The rules began as the Go relay's (gamerelay.io deploy/turn, before f9e9334); the node binary
//! owns the sockets.

pub mod auth;
pub mod budget;
pub mod counts;
pub mod limiter;
pub mod server;
pub mod stream;
pub mod stun;
pub mod ticket;

pub use server::{Client, Config, Output, Server, Stats};

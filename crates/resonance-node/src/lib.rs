//! A Resonance relay node's parts: the relay loop (`relay`), its TLS certificate (`tls`), the
//! control plane as a node talks to it (`control`), and what it keeps between runs (`state`). The
//! binary (main.rs) reads the settings and runs them.

pub mod control;
pub mod relay;
pub mod state;
pub mod tls;

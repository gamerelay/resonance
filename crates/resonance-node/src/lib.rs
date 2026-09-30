//! A Resonance relay node's parts: the relay loop (`relay`), its TLS certificate (`tls`), the
//! control plane as a node talks to it (`control`), what it keeps between runs (`state`), its
//! settings (`settings`), and how it measures the other nodes (`probe`). The binary (main.rs) puts them together.

pub mod control;
pub mod probe;
pub mod relay;
pub mod settings;
pub mod state;
pub mod tls;

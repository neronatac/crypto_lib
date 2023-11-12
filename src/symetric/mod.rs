//! Symetric ciphers.
//!
//! Ciphers are reparted in 2 categories:
//! - [block ciphers](block_ciphers)
//! - [stream ciphers](stream_ciphers)
//!
//! Also, chaining algorithms are defined in [block_ciphers_modes].

pub mod block_ciphers;
pub mod block_ciphers_modes;
pub mod stream_ciphers;
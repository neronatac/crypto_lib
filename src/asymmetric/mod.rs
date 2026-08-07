//! Asymmetric ciphers.
//!
//! Currently, these hash algorithms are implemented:
//! - RSA STD
//!
//! Each cipher exposes the `sign` and `verify` static methods.

mod common;

pub mod rsa;
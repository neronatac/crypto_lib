#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

//! Crate to do some crypto
//!
//! In order to make the code simpler, the feature `generic_const_exprs` is enabled (only on nightly builds).
//! It allows to use constants to define arrays (e.g. `key: [u8; KEY_SIZE];`).
//!
//! Algorithms are reparted in 3 categories:
//! - [symetric]
//! - [asymetric]
//! - [hash]

pub mod symetric;
pub mod hash;
mod utils;

#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

//! Crate to do some crypto
//!
//! In order to make the code simpler, the feature `generic_const_exprs` is enabled.
//! It allows to use constants to define arrays (e.g. `key: [u8; KEY_SIZE];`).
//!
//! Algorithms are reparted in 3 categories:
//! - [symetric](symetric)
//! - [asymetric](asymetric)
//! - [hash](hash)

pub mod symetric;
mod utils;

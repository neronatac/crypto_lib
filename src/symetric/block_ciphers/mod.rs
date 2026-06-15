//! Block ciphers.
//!
//! Currently, these ciphers are implemented:
//! - AES128 / AES192 / AES256
//! - DES / Triple-DES 2K / Triple-DES 3K
//!
//! Each cipher exposes the `cipher` and `decipher` static methods to
//! treat a single block of data (see [common::BlockCipher] for more details).
//!
//! # Example
//!
//! ```
//! use crate::crypto_lib::symetric::block_ciphers::common::BlockCipher;
//! use crypto_lib::symetric::block_ciphers::aes::AES128;
//! 
//! let plain = [0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A];
//! let key = [0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C];
//! let mut ciphertext = [0;16];
//! let expected = [0x3A, 0xD7, 0x7B, 0xB4, 0x0D, 0x7A, 0x36, 0x60, 0xA8, 0x9E, 0xCA, 0xF3, 0x24, 0x66, 0xEF, 0x97];
//!
//! AES128::cipher(&plain, &mut ciphertext, &key).expect("Error during AES128 execution");
//!
//! assert_eq!(ciphertext, expected);
//! ```

pub mod aes;
pub mod des;
pub mod triple_des;
pub mod common;
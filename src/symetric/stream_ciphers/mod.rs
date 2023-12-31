//! Stream ciphers.
//!
//! Currently, these ciphers are implemented:
//! - Salsa20/Salsa12/Salsa8 (32 and 16 bytes key)
//!
//! Each cipher exposes the `cipher` method to treat some data (see [common::StreamCipher] for more details).
//!
//! # Example
//!
//! ```
//! use crate::crypto_lib::symetric::stream_ciphers::common::StreamCipher;
//! use crypto_lib::symetric::stream_ciphers::salsa::{Salsa20K32, SalsaInitStruct};
//!
//! let nonce = 0x0011223344556677;
//!
//! let key = [
//!     0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
//!     0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
//!     0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
//!     0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
//! ];
//!
//! let plaintext1 = [
//!     0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
//!     0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
//!     0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
//!     0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
//!     0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
//!     0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
//!     0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
//!     0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
//!     0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
//!
//! let plaintext2 = [
//!     0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
//!     0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
//!     0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
//!     0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
//!     0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
//!     0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
//!     0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
//! ];
//!
//! let mut ciphertext1 = [0; 72];
//! let mut ciphertext2 = [0; 56];
//!
//!
//! let expected1 = [
//!     0x12, 0xde, 0x44, 0x05, 0x3e, 0x67, 0xf5, 0x12,
//!     0x8b, 0xa5, 0x10, 0x4e, 0x10, 0x3a, 0x4d, 0xf5,
//!     0xb0, 0x1b, 0xc8, 0xd2, 0x3f, 0x6e, 0xab, 0x61,
//!     0x2a, 0x0a, 0x7d, 0xa6, 0x4a, 0xc4, 0x1e, 0xaf,
//!     0x4d, 0x58, 0xb2, 0xed, 0xb0, 0xdb, 0xd0, 0xe9,
//!     0x48, 0xc3, 0x61, 0x80, 0xc4, 0x55, 0x20, 0xc2,
//!     0xba, 0x49, 0x2a, 0x4c, 0x4c, 0xde, 0x06, 0xe4,
//!     0x7a, 0xaa, 0xea, 0x43, 0xb0, 0x6d, 0xb6, 0x8b,
//!     0x60, 0x80, 0x08, 0xde, 0x04, 0x22, 0xf9, 0x07];
//!
//! let expected2 = [
//!     0x07, 0x2d, 0x5c, 0x70, 0x0c, 0x89, 0x51, 0xef,
//!     0xec, 0xcb, 0xe3, 0xb6, 0x5a, 0x45, 0xa8, 0xff,
//!     0x9a, 0xb5, 0x1c, 0xcd, 0xa7, 0xf2, 0xa6, 0x7f,
//!     0x38, 0xf4, 0x49, 0x74, 0x89, 0xe7, 0x12, 0x62,
//!     0x77, 0xf3, 0x48, 0xc6, 0xbb, 0xdd, 0xd4, 0x92,
//!     0xa8, 0x69, 0xd6, 0xac, 0x9d, 0xdb, 0x2f, 0x80,
//!     0x6a, 0x5d, 0x8e, 0xfb, 0xdf, 0x10, 0xb9, 0x86,
//! ];
//!
//! let mut salsa = Salsa20K32::new(&SalsaInitStruct{ nonce }, &key);
//! salsa.cipher(&plaintext1, &mut ciphertext1).expect("Error during Salsa20K32 test!");
//! salsa.cipher(&plaintext2, &mut ciphertext2).expect("Error during Salsa20K32 test!");
//! assert_eq!(ciphertext1, expected1);
//! assert_eq!(ciphertext2, expected2);
//! ```

pub mod common;
pub mod salsa;
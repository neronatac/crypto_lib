//! Hash algorithms.
//!
//! Currently, these hash algorithms are implemented:
//! - MD2
//!
//! Each cipher exposes the `update` and `finalise` methods to respectively treat some data and compute the final hash
//! (see [crate::hash::common] for more details).
//!
//! # Example
//!
//! ```
//! use crate::crypto_lib::hash::common::Hash;
//! use crypto_lib::hash::md2::MD2;
//!
//! let mut md2 = MD2::new(&());
//!
//! let data1 = "1234567".as_bytes();
//! let data2 = "890123456789012345678".as_bytes();
//! let data3 = "901234567890123456789012345678901234567890123456".as_bytes();
//! let data4 = "7890".as_bytes();
//!
//! md2.update(data1);
//! md2.update(data2);
//! md2.update(data3);
//! md2.update(data4);
//!
//! let res = md2.finalise();
//! assert_eq!(res, [0xd5, 0x97, 0x6f, 0x79, 0xd8, 0x3d, 0x3a, 0x0d, 0xc9, 0x80, 0x6c, 0x3c, 0x66, 0xf3, 0xef, 0xd8]);
//! ```

pub mod common;
pub mod md2;
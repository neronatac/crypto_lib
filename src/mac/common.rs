//! Shared code between MAC algorithms

/// Trait implemented by all MAC algorithms.
///
/// Each MAC has
/// - 2 types:
///     - `MACType`: type of the output
///     - `KeyType`: type of the key
/// - 1 method:
///     - `compute`: computes the MAC and returns it
pub trait MAC {
    type MACType;   // &[u8; xxx]
    type KeyType;

    fn compute(data: &[u8], key: Self::KeyType) -> Self::MACType;
}

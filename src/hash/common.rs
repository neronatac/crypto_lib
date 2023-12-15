//! Shared code between hash algorithms

/// Trait implemented by all hash algorithms.
///
/// Each hash has
/// - 1 constant:
///     - DIGEST_SIZE: size of the digest (in bytes)
/// - 2 types:
///     - `InitStruct`: structure used to initialise the context
///     - `Context`: type of the hash context (state and over stuff)
/// - 3 methods:
///     - `new`: static method that returns an initialised instance of the hash
///     - `update`: treats some data
///     - `finalise`: finalises the hash and returns it
///
/// Multiple calls to `update` can be done to treat the data as it was a single big block
/// (i.e. conceptually, `update(a, b) == update(a), update(b)`).
///
/// Do not call `update` after `finalise` was called.
pub trait Hash {
    type InitStruct;
    type Context;
    const DIGEST_SIZE: usize;

    fn new(init_struct: &Self::InitStruct) -> Self;
    fn update(&mut self, data: &[u8]);
    fn finalise(&mut self) -> [u8; Self::DIGEST_SIZE];
}
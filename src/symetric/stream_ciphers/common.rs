//! Shared code between stream ciphers

/// Trait implemented by all stream ciphers.
///
/// Each stream cipher has
/// - 1 constant:
///     - `KEY_SIZE`, expressed as bytes
/// - 2 types:
///     - `InitStruct`: structure used to initialise the state
///     - `State`: type of the cipher's state
/// - 4 methods:
///     - `new`: static method that returns an initialised instance of the stream cipher
///     - `cipher`: encrypts the `plaintext` and put the result in `ciphertext`
///
/// Inputs can be of any length (but the two `plaintext` and `ciphertext` buffers must have the same length).
/// Multiple calls to `cipher` can be done to treat the data as it was a single continuous block
/// (i.e. conceptually, `cipher(a, b) == cipher(a), cipher(b)`).
pub trait StreamCipher {
    const KEY_SIZE: usize;

    type InitStruct;
    type State;

    fn new(init_struct: &Self::InitStruct, key: &[u8; Self::KEY_SIZE]) -> Self;
    fn cipher(&mut self, plaintext: &[u8], ciphertext: &mut [u8]) -> Result<(), &'static str>;
}
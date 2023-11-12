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
///     - `from_state`: static method that constructs an instance of the stream cipher from the given state
///     - `get_state`: returns the current state
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
    fn from_state(state: &Self::State) -> Self;
    fn get_state(&self) -> Self::State;
    fn cipher(&mut self, plaintext: &[u8], ciphertext: &mut [u8]) -> Result<(), &'static str>;
}
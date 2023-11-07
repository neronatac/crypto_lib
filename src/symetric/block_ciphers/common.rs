pub trait BlockCipher {
    const KEY_SIZE: usize;
    const BLOCK_SIZE: usize;
    fn cipher(plaintext: &[u8; Self::BLOCK_SIZE], ciphertext: &mut [u8;Self::BLOCK_SIZE], key: &[u8; Self::KEY_SIZE]) -> Result<(), &'static str>;
    fn decipher(plaintext: &mut [u8;Self::BLOCK_SIZE], ciphertext: &[u8;Self::BLOCK_SIZE], key: &[u8; Self::KEY_SIZE]) -> Result<(), &'static str>;
}
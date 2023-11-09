//! Definition of CBC chaining mode
//!
//! Encryption:
//!```text
//!          P1        P2        Pn
//!          |         |         |
//!   IV ----+     ----+     ----+
//!          |    |    |    |    |
//!         ---   |   ---   |   ---
//!        | K |  |  | K | ... | K |
//!         ---   |   ---   |   ---
//!          |    |    |    |    |
//!          |----     |----     |
//!          |         |         |
//!          C1        C2        Cn
//!```
//!
//! Decryption:
//!```text
//!          C1        C2        Cn
//!          |         |         |
//!          |----     |----     |
//!          |    |    |    |    |
//!         ---   |   ---   |   ---
//!        | K |  |  | K | ... | K |
//!         ---   |   ---   |   ---
//!          |    |    |    |    |
//!   IV ----+     ----+     ----+
//!          |         |         |
//!          C1        C2        Cn
//! ```

use crate::symetric::block_ciphers_modes::common::{BlockChainingWithIV};
use crate::symetric::block_ciphers::common::BlockCipher;
use crate::utils::{check_cipher_params, extract_array_from_slice, xor_arrays};

pub struct CBC{}

impl<T> BlockChainingWithIV<T> for CBC
where
    T: BlockCipher,
{
    fn cipher(plaintext: &[u8], ciphertext: &mut [u8], key: &[u8; T::KEY_SIZE], iv: &[u8; T::BLOCK_SIZE]) -> Result<(), &'static str> {
        let mut last_cipher = *iv;

        // check parameters
        check_cipher_params(plaintext, ciphertext, T::BLOCK_SIZE)?;

        // do the chain
        let mut i = 0;
        while i < plaintext.len() {
            let mut chunk_p = extract_array_from_slice(plaintext, i)?;
            let mut chunk_c = extract_array_from_slice(ciphertext, i)?;

            chunk_p = xor_arrays(&chunk_p, &last_cipher);

            T::cipher(&chunk_p, &mut chunk_c, key)?;
            for j in 0..T::BLOCK_SIZE {
                ciphertext[i+j] = chunk_c[j].into();
            }
            last_cipher = chunk_c;
            i += T::BLOCK_SIZE;
        }

        return Ok(());
    }

    fn decipher(plaintext: &mut [u8], ciphertext: &[u8], key: &[u8; T::KEY_SIZE], iv: &[u8; T::BLOCK_SIZE]) -> Result<(), &'static str> {
        let mut last_cipher = *iv;

        // check parameters
        check_cipher_params(plaintext, ciphertext, T::BLOCK_SIZE)?;

        // do the chain
        let mut i = 0;
        while i < plaintext.len() {
            let mut chunk_p = extract_array_from_slice(plaintext, i)?;
            let chunk_c = extract_array_from_slice(ciphertext, i)?;

            T::decipher(&mut chunk_p, &chunk_c, key)?;
            let xored = xor_arrays(&chunk_p, &last_cipher);
            for j in 0..T::BLOCK_SIZE {
                plaintext[i+j] = xored[j];
            }
            last_cipher = chunk_c;
            i += T::BLOCK_SIZE;
        }

        return Ok(());
    }
}

#[cfg(test)]
mod tests_cbc {
    use crate::symetric::block_ciphers::aes::AES128;
    use super::*;

    #[test]
    fn cbc_encrypt_2_blocks() {
        let plain = [0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
            0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51];
        let key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        let iv = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
        let mut ciphertext = [0;32];
        let expected = [0x76, 0x49, 0xAB, 0xAC, 0x81, 0x19, 0xB2, 0x46, 0xCE, 0xE9, 0x8E, 0x9B, 0x12, 0xE9, 0x19, 0x7D,
            0x50, 0x86, 0xCB, 0x9B, 0x50, 0x72, 0x19, 0xEE, 0x95, 0xDB, 0x11, 0x3A, 0x91, 0x76, 0x78, 0xB2];
        <CBC as BlockChainingWithIV<AES128>>::cipher(&plain, &mut ciphertext, &key, &iv).expect("Error during CBC_AES128 execution");
        assert_eq!(ciphertext, expected);
    }

    #[test]
    fn cbc_encrypt_1_block() {
        let plain = [0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A];
        let key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        let iv = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
        let mut ciphertext = [0;16];
        let expected = [0x76, 0x49, 0xAB, 0xAC, 0x81, 0x19, 0xB2, 0x46, 0xCE, 0xE9, 0x8E, 0x9B, 0x12, 0xE9, 0x19, 0x7D];
        <CBC as BlockChainingWithIV<AES128>>::cipher(&plain, &mut ciphertext, &key, &iv).expect("Error during CBC_AES128 execution");
        assert_eq!(ciphertext, expected);
    }

    #[test]
    fn cbc_encrypt_bad_length() {
        let plain = [0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A];
        let key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        let iv = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
        let mut ciphertext = [0;15];
        let res = <CBC as BlockChainingWithIV<AES128>>::cipher(&plain, &mut ciphertext, &key, &iv);
        assert!(res.is_err());
    }

    #[test]
    fn cbc_encrypt_bad_length2() {
        let plain = [0x6B, 0xC1, 0xBE];
        let key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        let iv = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
        let mut ciphertext = [0;16];
        let res = <CBC as BlockChainingWithIV<AES128>>::cipher(&plain, &mut ciphertext, &key, &iv);
        assert!(res.is_err());
    }

    #[test]
    fn cbc_encrypt_bad_block_length() {
        let plain = [0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17];
        let key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        let iv = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
        let mut ciphertext = [0;15];
        let res = <CBC as BlockChainingWithIV<AES128>>::cipher(&plain, &mut ciphertext, &key, &iv);
        assert!(res.is_err());
    }

    #[test]
    fn cbc_decrypt_2_blocks() {
        let mut plain = [0;32];
        let key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        let iv = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
        let ciphertext = [0x76, 0x49, 0xAB, 0xAC, 0x81, 0x19, 0xB2, 0x46, 0xCE, 0xE9, 0x8E, 0x9B, 0x12, 0xE9, 0x19, 0x7D,
            0x50, 0x86, 0xCB, 0x9B, 0x50, 0x72, 0x19, 0xEE, 0x95, 0xDB, 0x11, 0x3A, 0x91, 0x76, 0x78, 0xB2];
        let expected = [0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
            0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51];
        <CBC as BlockChainingWithIV<AES128>>::decipher(&mut plain, &ciphertext, &key, &iv).expect("Error during CBC_AES128 execution");
        assert_eq!(plain, expected);
    }

    #[test]
    fn cbc_decrypt_1_block() {
        let mut plain = [0;16];
        let key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        let iv = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
        let ciphertext = [0x76, 0x49, 0xAB, 0xAC, 0x81, 0x19, 0xB2, 0x46, 0xCE, 0xE9, 0x8E, 0x9B, 0x12, 0xE9, 0x19, 0x7D];
        let expected = [0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A];
        <CBC as BlockChainingWithIV<AES128>>::decipher(&mut plain, &ciphertext, &key, &iv).expect("Error during CBC_AES128 execution");
        assert_eq!(plain, expected);
    }

    #[test]
    fn cbc_decrypt_bad_length() {
        let mut plain = [0;16];
        let key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        let iv = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
        let ciphertext = [0x76, 0x49, 0xAB, 0xAC, 0x81, 0x19, 0xB2, 0x46, 0xCE, 0xE9, 0x8E, 0x9B, 0x12, 0xE9, 0x19];
        let res = <CBC as BlockChainingWithIV<AES128>>::decipher(&mut plain, &ciphertext, &key, &iv);
        assert!(res.is_err());
    }

    #[test]
    fn cbc_decrypt_bad_length2() {
        let mut plain = [0;3];
        let key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        let iv = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
        let ciphertext = [0x76, 0x49, 0xAB, 0xAC, 0x81, 0x19, 0xB2, 0x46, 0xCE, 0xE9, 0x8E, 0x9B, 0x12, 0xE9, 0x19, 0x7D];
        let res = <CBC as BlockChainingWithIV<AES128>>::decipher(&mut plain, &ciphertext, &key, &iv);
        assert!(res.is_err());
    }

    #[test]
    fn cbc_decrypt_bad_block_length() {
        let mut plain = [0;15];
        let key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        let iv = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
        let ciphertext = [0x76, 0x49, 0xAB, 0xAC, 0x81, 0x19, 0xB2, 0x46, 0xCE, 0xE9, 0x8E, 0x9B, 0x12, 0xE9, 0x19];
        let res = <CBC as BlockChainingWithIV<AES128>>::decipher(&mut plain, &ciphertext, &key, &iv);
        assert!(res.is_err());
    }
}
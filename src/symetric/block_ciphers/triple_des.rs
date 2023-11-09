//! Definition of Triple-DES 2K and Triple-DES 3K

use crate::symetric::block_ciphers::common::BlockCipher;
use crate::symetric::block_ciphers::des::DES;
use crate::utils::extract_array_from_slice;

pub struct TripleDES2K {}
pub struct TripleDES3K {}

impl BlockCipher for TripleDES2K{
    const KEY_SIZE: usize = 16;
    const BLOCK_SIZE: usize = 8;

    fn cipher(plaintext: &[u8; Self::BLOCK_SIZE], ciphertext: &mut [u8;Self::BLOCK_SIZE], key: &[u8; Self::KEY_SIZE]) -> Result<(), &'static str> {
        let k1 = extract_array_from_slice(key.as_slice(), 0)?;
        let k2 = extract_array_from_slice(key.as_slice(), 8)?;

        let mut tmp_res1 = [0; 8];
        DES::cipher(plaintext, &mut tmp_res1, &k1).expect("Error during 1rst DES");

        let mut tmp_res2 = [0; 8];
        DES::decipher(&mut tmp_res2, &tmp_res1, &k2).expect("Error during 2nd DES");

        DES::cipher(&tmp_res2, ciphertext, &k1).expect("Error during 3rd DES");

        Ok(())
    }

    fn decipher(plaintext: &mut [u8;Self::BLOCK_SIZE], ciphertext: &[u8;Self::BLOCK_SIZE], key: &[u8; Self::KEY_SIZE]) -> Result<(), &'static str> {
        let k1 = extract_array_from_slice(key.as_slice(), 0)?;
        let k2 = extract_array_from_slice(key.as_slice(), 8)?;

        let mut tmp_res1 = [0; 8];
        DES::decipher(&mut tmp_res1, ciphertext, &k1).expect("Error during 1rst DES");

        let mut tmp_res2 = [0; 8];
        DES::cipher(&tmp_res1, &mut tmp_res2, &k2).expect("Error during 2nd DES");

        DES::decipher(plaintext, &tmp_res2, &k1).expect("Error during 3rd DES");

        Ok(())
    }
}

impl BlockCipher for TripleDES3K{
    const KEY_SIZE: usize = 24;
    const BLOCK_SIZE: usize = 8;

    fn cipher(plaintext: &[u8; Self::BLOCK_SIZE], ciphertext: &mut [u8;Self::BLOCK_SIZE], key: &[u8; Self::KEY_SIZE]) -> Result<(), &'static str> {
        let k1 = extract_array_from_slice(key.as_slice(), 0)?;
        let k2 = extract_array_from_slice(key.as_slice(), 8)?;
        let k3 = extract_array_from_slice(key.as_slice(), 16)?;

        let mut tmp_res1 = [0; 8];
        DES::cipher(plaintext, &mut tmp_res1, &k1).expect("Error during 1rst DES");

        let mut tmp_res2 = [0; 8];
        DES::decipher(&mut tmp_res2, &tmp_res1, &k2).expect("Error during 2nd DES");

        DES::cipher(&tmp_res2, ciphertext, &k3).expect("Error during 3rd DES");

        Ok(())
    }

    fn decipher(plaintext: &mut [u8;Self::BLOCK_SIZE], ciphertext: &[u8;Self::BLOCK_SIZE], key: &[u8; Self::KEY_SIZE]) -> Result<(), &'static str> {
        let k1 = extract_array_from_slice(key.as_slice(), 0)?;
        let k2 = extract_array_from_slice(key.as_slice(), 8)?;
        let k3 = extract_array_from_slice(key.as_slice(), 16)?;

        let mut tmp_res1 = [0; 8];
        DES::decipher(&mut tmp_res1, ciphertext, &k3).expect("Error during 1rst DES");

        let mut tmp_res2 = [0; 8];
        DES::cipher(&tmp_res1, &mut tmp_res2, &k2).expect("Error during 2nd DES");

        DES::decipher(plaintext, &tmp_res2, &k1).expect("Error during 3rd DES");

        Ok(())
    }
}


#[cfg(test)]
mod tests_triple_des {
    use super::*;

    #[test]
    fn triple_des_2k_encrypt() {
        let plain = [0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96];
        let key = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01];
        let mut ciphertext = [0; 8];
        let expected = [0x06, 0xED, 0xE3, 0xD8, 0x28, 0x84, 0x09, 0x0A];
        TripleDES2K::cipher(&plain, &mut ciphertext, &key).expect("Error during DES execution");
        assert_eq!(ciphertext, expected);
    }

    #[test]
    fn triple_des_2k_decrypt() {
        let mut plain = [0; 8];
        let key = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01];
        let ciphertext = [0x06, 0xED, 0xE3, 0xD8, 0x28, 0x84, 0x09, 0x0A];
        let expected = [0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96];
        TripleDES2K::decipher(&mut plain, &ciphertext, &key).expect("Error during DES execution");
        assert_eq!(plain, expected);
    }

    #[test]
    fn triple_des_3k_encrypt() {
        let plain = [0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96];
        let key = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01,
            0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23];
        let mut ciphertext = [0; 8];
        let expected = [0x71, 0x47, 0x72, 0xF3, 0x39, 0x84, 0x1D, 0x34];
        TripleDES3K::cipher(&plain, &mut ciphertext, &key).expect("Error during DES execution");
        assert_eq!(ciphertext, expected);
    }

    #[test]
    fn triple_des_3k_decrypt() {
        let mut plain = [0; 8];
        let key = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01,
            0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23];
        let ciphertext = [0x71, 0x47, 0x72, 0xF3, 0x39, 0x84, 0x1D, 0x34];
        let expected = [0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96];
        TripleDES3K::decipher(&mut plain, &ciphertext, &key).expect("Error during DES execution");
        assert_eq!(plain, expected);
    }
}

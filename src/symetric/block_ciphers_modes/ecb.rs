use crate::symetric::block_ciphers_modes::common::BlockChaining;
use crate::symetric::block_ciphers::common::BlockCipher;
use std::ops::Index;

pub struct ECB {}

impl<T> BlockChaining<T> for ECB
where
    T: BlockCipher,
    <T as BlockCipher>::BlockType: Copy,
    <<T as BlockCipher>::BlockType as Index<usize>>::Output: Into<u8>,
    <<T as BlockCipher>::BlockType as Index<usize>>::Output: Copy
{
    fn cipher(&self, cipher: &T, plaintext: &[u8], ciphertext: &mut [u8], key: &T::KeyType) -> Result<(), &'static str> {
        let bs = T::block_size();

        // check parameters
        if plaintext.len() != ciphertext.len() {
            return Err("Plaintext and ciphertext must have the same length");
        } else if plaintext.len() % bs != 0 {
            return Err("Length of plain/ciphertext is not a multiple of block size")
        }

        // do the chain
        let mut i = 0;
        while i < plaintext.len() {
            let chunk_p = match plaintext[i..i + bs].try_into() {
                Ok(v) => {v}
                Err(_) => {return Err("Error during ECB chaining");}
            };
            let mut chunk_c = match ciphertext[i..i + bs].try_into() {
                Ok(v) => {v}
                Err(_) => {return Err("Error during ECB chaining");}
            };
            match cipher.cipher(&chunk_p, &mut chunk_c, key) {
                Ok(_) => {
                    for j in 0..bs {
                        ciphertext[i+j] = chunk_c[j].into();
                    }
                }
                Err(e) => {return Err(e);}
            }
            i += bs;
        }

        return Ok(());
    }

    fn decipher(&self, cipher: &T, plaintext: &mut [u8], ciphertext: &[u8], key: &T::KeyType) -> Result<(), &'static str> {
        let bs = T::block_size();

        // check parameters
        if plaintext.len() != ciphertext.len() {
            return Err("Plaintext and ciphertext must have the same length");
        } else if plaintext.len() % bs != 0 {
            return Err("Length of plain/ciphertext is not a multiple of block size")
        }

        // do the chain
        let mut i = 0;
        while i < plaintext.len() {
            let mut chunk_p = match plaintext[i..i + bs].try_into() {
                Ok(v) => {v}
                Err(_) => {return Err("Error during ECB chaining");}
            };
            let chunk_c = match ciphertext[i..i + bs].try_into() {
                Ok(v) => {v}
                Err(_) => {return Err("Error during ECB chaining");}
            };
            match cipher.decipher(&mut chunk_p, &chunk_c, key) {
                Ok(_) => {
                    for j in 0..bs {
                        plaintext[i+j] = chunk_p[j].into();
                    }
                }
                Err(e) => {return Err(e);}
            }
            i += bs;
        }

        return Ok(());
    }
}

#[cfg(test)]
mod tests_ecb {
    use crate::symetric::block_ciphers::aes::AES128;
    use super::*;

    #[test]
    fn ecb_encrypt_2_blocks() {
        let plain = [0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A, 0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A];
        let key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        let mut ciphertext = [0;32];
        let expected = [0x3A, 0xD7, 0x7B, 0xB4, 0x0D, 0x7A, 0x36, 0x60, 0xA8, 0x9E, 0xCA, 0xF3, 0x24, 0x66, 0xEF, 0x97, 0x3A, 0xD7, 0x7B, 0xB4, 0x0D, 0x7A, 0x36, 0x60, 0xA8, 0x9E, 0xCA, 0xF3, 0x24, 0x66, 0xEF, 0x97];
        let ecb = ECB{};
        ecb.cipher(&AES128{}, &plain, &mut ciphertext, &key).expect("Error during ECB_AES128 execution");
        assert_eq!(ciphertext, expected);
    }

    #[test]
    fn ecb_encrypt_1_block() {
        let plain = [0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A];
        let key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        let mut ciphertext = [0;16];
        let expected = [0x3A, 0xD7, 0x7B, 0xB4, 0x0D, 0x7A, 0x36, 0x60, 0xA8, 0x9E, 0xCA, 0xF3, 0x24, 0x66, 0xEF, 0x97];
        let ecb = ECB{};
        ecb.cipher(&AES128{}, &plain, &mut ciphertext, &key).expect("Error during ECB_AES128 execution");
        assert_eq!(ciphertext, expected);
    }

    #[test]
    fn ecb_encrypt_bad_length() {
        let plain = [0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A];
        let key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        let mut ciphertext = [0;15];
        let ecb = ECB{};
        let res = ecb.cipher(&AES128{}, &plain, &mut ciphertext, &key);
        assert!(res.is_err());
    }

    #[test]
    fn ecb_encrypt_bad_length2() {
        let plain = [0x6B, 0xC1, 0xBE];
        let key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        let mut ciphertext = [0;16];
        let ecb = ECB{};
        let res = ecb.cipher(&AES128{}, &plain, &mut ciphertext, &key);
        assert!(res.is_err());
    }

    #[test]
    fn ecb_encrypt_bad_block_length() {
        let plain = [0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17];
        let key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        let mut ciphertext = [0;15];
        let ecb = ECB{};
        let res = ecb.cipher(&AES128{}, &plain, &mut ciphertext, &key);
        assert!(res.is_err());
    }

    #[test]
    fn ecb_decrypt_2_blocks() {
        let mut plain = [0;32];
        let key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        let ciphertext = [0x3A, 0xD7, 0x7B, 0xB4, 0x0D, 0x7A, 0x36, 0x60, 0xA8, 0x9E, 0xCA, 0xF3, 0x24, 0x66, 0xEF, 0x97, 0x3A, 0xD7, 0x7B, 0xB4, 0x0D, 0x7A, 0x36, 0x60, 0xA8, 0x9E, 0xCA, 0xF3, 0x24, 0x66, 0xEF, 0x97];
        let expected = [0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A, 0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A];
        let ecb = ECB{};
        ecb.decipher(&AES128{}, &mut plain, &ciphertext, &key).expect("Error during ECB_AES128 execution");
        assert_eq!(plain, expected);
    }

    #[test]
    fn ecb_decrypt_1_block() {
        let mut plain = [0;16];
        let key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        let ciphertext = [0x3A, 0xD7, 0x7B, 0xB4, 0x0D, 0x7A, 0x36, 0x60, 0xA8, 0x9E, 0xCA, 0xF3, 0x24, 0x66, 0xEF, 0x97];
        let expected = [0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A];
        let ecb = ECB{};
        ecb.decipher(&AES128{}, &mut plain, &ciphertext, &key).expect("Error during ECB_AES128 execution");
        assert_eq!(plain, expected);
    }

    #[test]
    fn ecb_decrypt_bad_length() {
        let mut plain = [0;16];
        let key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        let ciphertext = [0x3A, 0xD7, 0x7B, 0xB4, 0x0D, 0x7A, 0x36, 0x60, 0xA8, 0x9E, 0xCA, 0xF3, 0x24, 0x66, 0xEF];
        let ecb = ECB{};
        let res = ecb.decipher(&AES128{}, &mut plain, &ciphertext, &key);
        assert!(res.is_err());
    }

    #[test]
    fn ecb_decrypt_bad_length2() {
        let mut plain = [0;3];
        let key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        let ciphertext = [0x3A, 0xD7, 0x7B, 0xB4, 0x0D, 0x7A, 0x36, 0x60, 0xA8, 0x9E, 0xCA, 0xF3, 0x24, 0x66, 0xEF, 0x97];
        let ecb = ECB{};
        let res = ecb.decipher(&AES128{}, &mut plain, &ciphertext, &key);
        assert!(res.is_err());
    }

    #[test]
    fn ecb_decrypt_bad_block_length() {
        let mut plain = [0;15];
        let key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        let ciphertext = [0x3A, 0xD7, 0x7B, 0xB4, 0x0D, 0x7A, 0x36, 0x60, 0xA8, 0x9E, 0xCA, 0xF3, 0x24, 0x66, 0xEF];
        let ecb = ECB{};
        let res = ecb.decipher(&AES128{}, &mut plain, &ciphertext, &key);
        assert!(res.is_err());
    }
}
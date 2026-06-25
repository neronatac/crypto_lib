//! Definition of SHA algorithms

// see FIPS 180, RFC3174

use std::ops::Shr;
use paste::paste;
use crate::hash::common::{generic_update_func, Hash};


fn sha0_expansion(w: &mut [u32; 80]) {
    for t in 16..80 {
        w[t] = w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16];
    }
}


fn sha1_expansion(w: &mut [u32; 80]) {
    for t in 16..80 {
        w[t] = (w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]).rotate_left(1);
    }
}


fn sha256_expansion(w: &mut [u32; 64]) {
    let sigma0 = |x: u32| -> u32 {
        x.rotate_right(7) ^ x.rotate_right(18) ^ x.shr(3)
    };
    let sigma1 = |x: u32| -> u32 {
        x.rotate_right(17) ^ x.rotate_right(19) ^ x.shr(10)
    };
    for t in 16..64 {
        w[t] = sigma1(w[t - 2])
            .wrapping_add(w[t-7])
            .wrapping_add(sigma0(w[t - 15]))
            .wrapping_add(w[t - 16]);
    }
}


fn sha0_round(round: usize, wv: &mut [u32; 5], w: &[u32; 80]) {
    let tmp = wv[0]
        .rotate_left(5)
        .wrapping_add(match round {
            0..=19 => (wv[1] & wv[2]) | (!wv[1] & wv[3]),
            20..=39 => wv[1] ^ wv[2] ^ wv[3],
            40..=59 => (wv[1] & wv[2]) | (wv[1] & wv[3]) | (wv[2] & wv[3]),
            60..=79 => wv[1] ^ wv[2] ^ wv[3],
            _ => unreachable!(),
        })
        .wrapping_add(wv[4])
        .wrapping_add(w[round])
        .wrapping_add(match round {
            0..=19 => 0x5A827999,
            20..=39 => 0x6ED9EBA1,
            40..=59 => 0x8F1BBCDC,
            60..=79 => 0xCA62C1D6,
            _ => unreachable!(),
        });
    wv[4] = wv[3];
    wv[3] = wv[2];
    wv[2] = wv[1].rotate_left(30);
    wv[1] = wv[0];
    wv[0] = tmp;
}

use sha0_round as sha1_round;


fn sha256_round(round: usize, wv: &mut [u32; 8], w: &[u32; 64]) {
    let ch = |x: u32, y: u32, z: u32| -> u32 {
        (x & y) ^ (!x & z)
    };
    let maj = |x: u32, y: u32, z: u32| -> u32 {
        (x & y) ^ (x & z) ^ (y & z)
    };
    let sigma0 = |x: u32| -> u32 {
        x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
    };
    let sigma1 = |x: u32| -> u32 {
        x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
    };
    let k: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    let t1 = wv[7]
        .wrapping_add(sigma1(wv[4]))
        .wrapping_add(ch(wv[4], wv[5], wv[6]))
        .wrapping_add(k[round])
        .wrapping_add(w[round]);

    let t2 = sigma0(wv[0])
        .wrapping_add(maj(wv[0], wv[1], wv[2]));

    wv[7] = wv[6];
    wv[6] = wv[5];
    wv[5] = wv[4];
    wv[4] = wv[3].wrapping_add(t1);
    wv[3] = wv[2];
    wv[2] = wv[1];
    wv[1] = wv[0];
    wv[0] = t1.wrapping_add(t2);
}


const SHA0_INIT_STATE: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
const SHA1_INIT_STATE: [u32; 5] = SHA0_INIT_STATE;
const SHA256_INIT_STATE: [u32; 8] = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];


macro_rules! create_sha {
    (0) => {create_sha!(@internal 0, u32, 5, 64, 20, 80);};
    (1) => {create_sha!(@internal 1, u32, 5, 64, 20, 80);};
    (256) => {create_sha!(@internal 256, u32, 8, 64, 32, 64);};

    (@internal
        $sha_number:literal,
        $state_words_type:ty,
        $state_words_nbr:literal,
        $block_size:literal, // bytes
        $digest_size:literal, // bytes
        $rounds:literal
    ) => {
        paste! {
            pub struct [< SHA $sha_number Context>] {
                state: [$state_words_type; $state_words_nbr],
            }

            pub struct [< SHA $sha_number>] {
                context: [< SHA $sha_number Context>],
                remaining_bytes: [u8; $block_size-1],
                remaining_bytes_len: usize,
                msg_length: u64 // in bits
            }

            impl Hash for [< SHA $sha_number>] {
                const DIGEST_SIZE: usize = $digest_size;
                const BLOCK_SIZE: usize = $block_size;

                type DigestType = [u8; Self::DIGEST_SIZE];
                type InitStruct = ();
                type Context = [< SHA $sha_number Context>];

                fn new(_: &Self::InitStruct) -> Self {
                    [< SHA $sha_number>] {
                        context: Self::Context {
                            state: [< SHA $sha_number _INIT_STATE>],
                        },
                        remaining_bytes: [0; $block_size-1],
                        remaining_bytes_len: 0,
                        msg_length: 0,
                    }
                }

                generic_update_func!([< process_block_sha $sha_number>] u64);

                fn finalise(&mut self) -> Self::DigestType {
                    let mut cur_block = [0; $block_size];

                    // take remaining bytes from the previous uncompleted block
                    for i in 0..self.remaining_bytes_len {
                        cur_block[i] = self.remaining_bytes[i];
                    }

                    // pad
                    cur_block[self.remaining_bytes_len] = 0x80;
                    if self.remaining_bytes_len >= $block_size-std::mem::size_of::<u64>() {
                        [< process_block_sha $sha_number>](&mut self.context, &cur_block);
                        cur_block.fill(0);
                    }

                    // append msg length
                    let len_bytes = self.msg_length.to_be_bytes();
                    for i in 0..std::mem::size_of::<u64>() {
                        cur_block[$block_size-std::mem::size_of::<u64>() + i] = len_bytes[i];
                    }

                    // process padded block
                    [< process_block_sha $sha_number>](&mut self.context, &cur_block);

                    // return digest
                    let mut ret = [0; $digest_size];
                    for i in 0..$state_words_nbr {
                        ret[i * std::mem::size_of::<$state_words_type>()..(i+1) * std::mem::size_of::<$state_words_type>()].copy_from_slice(&self.context.state[i].to_be_bytes());
                    }
                    ret
                }
            }

            fn [< process_block_sha $sha_number >](context: &mut [< SHA $sha_number Context>], block: &[u8; $block_size]) {
                // transform block into words
                let mut w = [0; $rounds];
                for i in 0..16 {
                    w[i] = $state_words_type::from_be_bytes(block[i * std::mem::size_of::<$state_words_type>()..(i+1) * std::mem::size_of::<$state_words_type>()].try_into().unwrap());
                }

                // expand until w[79]
                [< sha $sha_number _expansion>](&mut w);

                // get working variables (a, b, ...)
                let mut wv = context.state.clone();

                // do rounds
                for t in 0..$rounds {
                    [< sha $sha_number _round>](t, &mut wv, &w);
                }

                // final addition
                for i in 0..$state_words_nbr {
                    context.state[i] = context.state[i].wrapping_add(wv[i]);
                }
            }
        }
    };
}

create_sha!(0);
create_sha!(1);
create_sha!(256);


#[cfg(test)]
mod tests_sha0 {
    use super::*;

    #[test]
    fn test_abc() {
        let mut sha0 = SHA0::new(&());

        let data = "abc".as_bytes();

        sha0.update(&data);

        let res = sha0.finalise();
        assert_eq!(res, [0x01, 0x64, 0xB8, 0xA9, 0x14, 0xCD, 0x2A, 0x5E, 0x74, 0xC4, 0xF7, 0xFF, 0x08, 0x2C, 0x4D, 0x97, 0xF1, 0xED, 0xF8, 0x80]);
    }

    #[test]
    fn test_padding_two_blocs() {
        let mut sha0 = SHA0::new(&());

        let data = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".as_bytes();

        sha0.update(&data);

        let res = sha0.finalise();
        assert_eq!(res, [0xD2, 0x51, 0x6E, 0xE1, 0xAC, 0xFA, 0x5B, 0xAF, 0x33, 0xDF, 0xC1, 0xC4, 0x71, 0xE4, 0x38, 0x44, 0x9E, 0xF1, 0x34, 0xC8]);
    }

    #[test]
    fn test_big() {
        let mut sha0 = SHA0::new(&());

        let data = "12345678901234567890123456789012345678901234567890123456789012345678901234567890".as_bytes();

        sha0.update(&data);

        let res = sha0.finalise();
        assert_eq!(res, [0x4a, 0xa2, 0x9d, 0x14, 0xd1, 0x71, 0x52, 0x2e, 0xce, 0x47, 0xbe, 0xe8, 0x95, 0x7e, 0x35, 0xa4, 0x1f, 0x3e, 0x9c, 0xff]);
    }

    #[test]
    fn test_big_splitted() {
        let mut sha0 = SHA0::new(&());

        let data1 = "1234567".as_bytes();
        let data2 = "890123456789012345678".as_bytes();
        let data3 = "901234567890123456789012345678901234567890123456".as_bytes();
        let data4 = "7890".as_bytes();

        sha0.update(data1);
        sha0.update(data2);
        sha0.update(data3);
        sha0.update(data4);

        let res = sha0.finalise();
        assert_eq!(res, [0x4a, 0xa2, 0x9d, 0x14, 0xd1, 0x71, 0x52, 0x2e, 0xce, 0x47, 0xbe, 0xe8, 0x95, 0x7e, 0x35, 0xa4, 0x1f, 0x3e, 0x9c, 0xff]);
    }

    #[test]
    fn test_bigbig() {
        let mut sha0 = SHA0::new(&());

        let data = "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890".as_bytes();

        sha0.update(&data);

        let res = sha0.finalise();
        assert_eq!(res, [0xbc, 0xbe, 0xd6, 0xdd, 0x21, 0x56, 0xbf, 0x13, 0x5d, 0x42, 0x19, 0x81, 0x24, 0x9a, 0xcd, 0xd3, 0xc9, 0x73, 0x4d, 0x1f]);
    }
}

#[cfg(test)]
mod tests_sha1 {
    use super::*;

    #[test]
    fn test_abc() {
        let mut sha1 = SHA1::new(&());

        let data = "abc".as_bytes();

        sha1.update(&data);

        let res = sha1.finalise();
        assert_eq!(res, [0xA9, 0x99, 0x3E, 0x36, 0x47, 0x06, 0x81, 0x6A, 0xBA, 0x3E, 0x25, 0x71, 0x78, 0x50, 0xC2, 0x6C, 0x9C, 0xD0, 0xD8, 0x9D]);
    }

    #[test]
    fn test_padding_two_blocs() {
        let mut sha1 = SHA1::new(&());

        let data = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".as_bytes();

        sha1.update(&data);

        let res = sha1.finalise();
        assert_eq!(res, [0x84, 0x98, 0x3E, 0x44, 0x1C, 0x3B, 0xD2, 0x6E, 0xBA, 0xAE, 0x4A, 0xA1, 0xF9, 0x51, 0x29, 0xE5, 0xE5, 0x46, 0x70, 0xF1]);
    }

    #[test]
    fn test_big() {
        let mut sha1 = SHA1::new(&());

        let data = "12345678901234567890123456789012345678901234567890123456789012345678901234567890".as_bytes();

        sha1.update(&data);

        let res = sha1.finalise();
        assert_eq!(res, [0x50, 0xab, 0xf5, 0x70, 0x6a, 0x15, 0x09, 0x90, 0xa0, 0x8b, 0x2c, 0x5e, 0xa4, 0x0f, 0xa0, 0xe5, 0x85, 0x55, 0x47, 0x32]);
    }

    #[test]
    fn test_big_splitted() {
        let mut sha1 = SHA1::new(&());

        let data1 = "1234567".as_bytes();
        let data2 = "890123456789012345678".as_bytes();
        let data3 = "901234567890123456789012345678901234567890123456".as_bytes();
        let data4 = "7890".as_bytes();

        sha1.update(data1);
        sha1.update(data2);
        sha1.update(data3);
        sha1.update(data4);

        let res = sha1.finalise();
        assert_eq!(res, [0x50, 0xab, 0xf5, 0x70, 0x6a, 0x15, 0x09, 0x90, 0xa0, 0x8b, 0x2c, 0x5e, 0xa4, 0x0f, 0xa0, 0xe5, 0x85, 0x55, 0x47, 0x32]);
    }

    #[test]
    fn test_bigbig() {
        let mut sha1 = SHA1::new(&());

        let data = "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890".as_bytes();

        sha1.update(&data);

        let res = sha1.finalise();
        assert_eq!(res, [0x9a, 0xb9, 0xa9, 0x73, 0xce, 0x40, 0x3f, 0x31, 0xfe, 0x04, 0x15, 0x42, 0x1d, 0xc3, 0x60, 0x8d, 0xf7, 0x24, 0x61, 0x3c]);
    }
}


#[cfg(test)]
mod tests_sha256 {
    use super::*;

    #[test]
    fn test_abc() {
        let mut sha256 = SHA256::new(&());

        let data = "abc".as_bytes();

        sha256.update(&data);

        let res = sha256.finalise();
        assert_eq!(res, [0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad]);
    }

    #[test]
    fn test_padding_two_blocs() {
        let mut sha256 = SHA256::new(&());

        let data = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".as_bytes();

        sha256.update(&data);

        let res = sha256.finalise();
        assert_eq!(res, [0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39, 0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67, 0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1]);
    }

    #[test]
    fn test_big() {
        let mut sha256 = SHA256::new(&());

        let data = "12345678901234567890123456789012345678901234567890123456789012345678901234567890".as_bytes();

        sha256.update(&data);

        let res = sha256.finalise();
        assert_eq!(res, [0xf3, 0x71, 0xbc, 0x4a, 0x31, 0x1f, 0x2b, 0x00, 0x9e, 0xef, 0x95, 0x2d, 0xd8, 0x3c, 0xa8, 0x0e, 0x2b, 0x60, 0x02, 0x6c, 0x8e, 0x93, 0x55, 0x92, 0xd0, 0xf9, 0xc3, 0x08, 0x45, 0x3c, 0x81, 0x3e]);
    }

    #[test]
    fn test_big_splitted() {
        let mut sha256 = SHA256::new(&());

        let data1 = "1234567".as_bytes();
        let data2 = "890123456789012345678".as_bytes();
        let data3 = "901234567890123456789012345678901234567890123456".as_bytes();
        let data4 = "7890".as_bytes();

        sha256.update(data1);
        sha256.update(data2);
        sha256.update(data3);
        sha256.update(data4);

        let res = sha256.finalise();
        assert_eq!(res, [0xf3, 0x71, 0xbc, 0x4a, 0x31, 0x1f, 0x2b, 0x00, 0x9e, 0xef, 0x95, 0x2d, 0xd8, 0x3c, 0xa8, 0x0e, 0x2b, 0x60, 0x02, 0x6c, 0x8e, 0x93, 0x55, 0x92, 0xd0, 0xf9, 0xc3, 0x08, 0x45, 0x3c, 0x81, 0x3e]);
    }

    #[test]
    fn test_bigbig() {
        let mut sha256 = SHA256::new(&());

        let data = "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890".as_bytes();

        sha256.update(&data);

        let res = sha256.finalise();
        assert_eq!(res, [0xb0, 0x36, 0x49, 0x6b, 0x6c, 0x63, 0x0d, 0xe4, 0xac, 0x9a, 0xc3, 0x33, 0x77, 0xc7, 0x0d, 0x58, 0xca, 0x04, 0xb9, 0xac, 0x4d, 0x3c, 0x78, 0xd2, 0xeb, 0x25, 0xe6, 0x84, 0x6f, 0xfd, 0x65, 0x08]);
    }
}

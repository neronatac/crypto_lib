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


fn sha512_expansion(w: &mut [u64; 80]) {
    let sigma0 = |x: u64| -> u64 {
        x.rotate_right(1) ^ x.rotate_right(8) ^ x.shr(7)
    };
    let sigma1 = |x: u64| -> u64 {
        x.rotate_right(19) ^ x.rotate_right(61) ^ x.shr(6)
    };
    for t in 16..80 {
        w[t] = sigma1(w[t - 2])
            .wrapping_add(w[t-7])
            .wrapping_add(sigma0(w[t - 15]))
            .wrapping_add(w[t - 16]);
    }
}

use sha512_expansion as sha384_expansion;


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


fn sha512_round(round: usize, wv: &mut [u64; 8], w: &[u64; 80]) {
    let ch = |x: u64, y: u64, z: u64| -> u64 {
        (x & y) ^ (!x & z)
    };
    let maj = |x: u64, y: u64, z: u64| -> u64 {
        (x & y) ^ (x & z) ^ (y & z)
    };
    let sigma0 = |x: u64| -> u64 {
        x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39)
    };
    let sigma1 = |x: u64| -> u64 {
        x.rotate_right(14) ^ x.rotate_right(18) ^ x.rotate_right(41)
    };
    let k: [u64; 80] = [
        0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
        0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
        0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
        0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
        0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
        0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
        0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
        0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
        0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
        0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
        0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
        0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
        0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
        0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
        0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
        0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
        0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
        0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
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

use sha512_round as sha384_round;


const SHA0_INIT_STATE: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
const SHA1_INIT_STATE: [u32; 5] = SHA0_INIT_STATE;
const SHA256_INIT_STATE: [u32; 8] = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
const SHA512_INIT_STATE: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179
];
const SHA384_INIT_STATE: [u64; 8] = [
    0xcbbb9d5dc1059ed8,
    0x629a292a367cd507,
    0x9159015a3070dd17,
    0x152fecd8f70e5939,
    0x67332667ffc00b31,
    0x8eb44a8768581511,
    0xdb0c2e0d64f98fa7,
    0x47b5481dbefa4fa4
];


macro_rules! create_sha {
    (0) => {create_sha!(@internal 0, u32, 5, 64, 20, 80, u64);};
    (1) => {create_sha!(@internal 1, u32, 5, 64, 20, 80, u64);};
    (256) => {create_sha!(@internal 256, u32, 8, 64, 32, 64, u64);};
    (384) => {create_sha!(@internal 384, u64, 8, 128, 48, 80, u128);};
    (512) => {create_sha!(@internal 512, u64, 8, 128, 64, 80, u128);};

    (@internal
        $sha_number:literal,
        $state_words_type:ty,
        $state_words_nbr:literal,
        $block_size:literal, // bytes
        $digest_size:literal, // bytes
        $rounds:literal,
        $msg_length_type:ty
    ) => {
        paste! {
            pub struct [< SHA $sha_number Context>] {
                state: [$state_words_type; $state_words_nbr],
            }

            pub struct [< SHA $sha_number>] {
                context: [< SHA $sha_number Context>],
                remaining_bytes: [u8; $block_size-1],
                remaining_bytes_len: usize,
                msg_length: $msg_length_type // in bits
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

                generic_update_func!([< process_block_sha $sha_number>] $msg_length_type);

                fn finalise(&mut self) -> Self::DigestType {
                    let mut cur_block = [0; $block_size];

                    // take remaining bytes from the previous uncompleted block
                    for i in 0..self.remaining_bytes_len {
                        cur_block[i] = self.remaining_bytes[i];
                    }

                    // pad
                    cur_block[self.remaining_bytes_len] = 0x80;
                    if self.remaining_bytes_len >= $block_size-std::mem::size_of::<$msg_length_type>() {
                        [< process_block_sha $sha_number>](&mut self.context, &cur_block);
                        cur_block.fill(0);
                    }

                    // append msg length
                    let len_bytes = self.msg_length.to_be_bytes();
                    for i in 0..std::mem::size_of::<$msg_length_type>() {
                        cur_block[$block_size-std::mem::size_of::<$msg_length_type>() + i] = len_bytes[i];
                    }

                    // process padded block
                    [< process_block_sha $sha_number>](&mut self.context, &cur_block);

                    // return digest
                    let mut ret = [0; $digest_size];
                    for i in 0..$digest_size/std::mem::size_of::<$state_words_type>() {
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
create_sha!(384);
create_sha!(512);


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

#[cfg(test)]
mod tests_sha512 {
    use super::*;

    #[test]
    fn test_abc() {
        let mut sha512 = SHA512::new(&());

        let data = "abc".as_bytes();

        sha512.update(&data);

        let res = sha512.finalise();
        assert_eq!(res, [0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31, 0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a, 0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd, 0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e, 0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f]);
    }

    #[test]
    fn test_padding_two_blocs() {
        let mut sha512 = SHA512::new(&());

        let data = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".as_bytes();

        sha512.update(&data);

        let res = sha512.finalise();
        assert_eq!(res, [0x20, 0x4a, 0x8f, 0xc6, 0xdd, 0xa8, 0x2f, 0x0a, 0x0c, 0xed, 0x7b, 0xeb, 0x8e, 0x08, 0xa4, 0x16, 0x57, 0xc1, 0x6e, 0xf4, 0x68, 0xb2, 0x28, 0xa8, 0x27, 0x9b, 0xe3, 0x31, 0xa7, 0x03, 0xc3, 0x35, 0x96, 0xfd, 0x15, 0xc1, 0x3b, 0x1b, 0x07, 0xf9, 0xaa, 0x1d, 0x3b, 0xea, 0x57, 0x78, 0x9c, 0xa0, 0x31, 0xad, 0x85, 0xc7, 0xa7, 0x1d, 0xd7, 0x03, 0x54, 0xec, 0x63, 0x12, 0x38, 0xca, 0x34, 0x45]);
    }

    #[test]
    fn test_big() {
        let mut sha512 = SHA512::new(&());

        let data = "12345678901234567890123456789012345678901234567890123456789012345678901234567890".as_bytes();

        sha512.update(&data);

        let res = sha512.finalise();
        assert_eq!(res, [0x72, 0xec, 0x1e, 0xf1, 0x12, 0x4a, 0x45, 0xb0, 0x47, 0xe8, 0xb7, 0xc7, 0x5a, 0x93, 0x21, 0x95, 0x13, 0x5b, 0xb6, 0x1d, 0xe2, 0x4e, 0xc0, 0xd1, 0x91, 0x40, 0x42, 0x24, 0x6e, 0x0a, 0xec, 0x3a, 0x23, 0x54, 0xe0, 0x93, 0xd7, 0x6f, 0x30, 0x48, 0xb4, 0x56, 0x76, 0x43, 0x46, 0x90, 0x0c, 0xb1, 0x30, 0xd2, 0xa4, 0xfd, 0x5d, 0xd1, 0x6a, 0xbb, 0x5e, 0x30, 0xbc, 0xb8, 0x50, 0xde, 0xe8, 0x43]);
    }

    #[test]
    fn test_big_splitted() {
        let mut sha512 = SHA512::new(&());

        let data1 = "1234567".as_bytes();
        let data2 = "890123456789012345678".as_bytes();
        let data3 = "901234567890123456789012345678901234567890123456".as_bytes();
        let data4 = "7890".as_bytes();

        sha512.update(data1);
        sha512.update(data2);
        sha512.update(data3);
        sha512.update(data4);

        let res = sha512.finalise();
        assert_eq!(res, [0x72, 0xec, 0x1e, 0xf1, 0x12, 0x4a, 0x45, 0xb0, 0x47, 0xe8, 0xb7, 0xc7, 0x5a, 0x93, 0x21, 0x95, 0x13, 0x5b, 0xb6, 0x1d, 0xe2, 0x4e, 0xc0, 0xd1, 0x91, 0x40, 0x42, 0x24, 0x6e, 0x0a, 0xec, 0x3a, 0x23, 0x54, 0xe0, 0x93, 0xd7, 0x6f, 0x30, 0x48, 0xb4, 0x56, 0x76, 0x43, 0x46, 0x90, 0x0c, 0xb1, 0x30, 0xd2, 0xa4, 0xfd, 0x5d, 0xd1, 0x6a, 0xbb, 0x5e, 0x30, 0xbc, 0xb8, 0x50, 0xde, 0xe8, 0x43]);
    }

    #[test]
    fn test_bigbig() {
        let mut sha512 = SHA512::new(&());

        let data = "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890".as_bytes();

        sha512.update(&data);

        let res = sha512.finalise();
        assert_eq!(res, [0x33, 0xf8, 0x90, 0x1b, 0x05, 0x3e, 0x4c, 0xc6, 0x77, 0xd3, 0xcb, 0x41, 0x22, 0xd9, 0x6a, 0xd9, 0xb9, 0x6b, 0x13, 0xbf, 0x76, 0x19, 0x4c, 0xf9, 0x62, 0x48, 0x8b, 0xb4, 0xde, 0x49, 0x98, 0xa7, 0x14, 0x55, 0xcb, 0x31, 0x58, 0x2d, 0xb5, 0x27, 0xad, 0xf7, 0x7a, 0x48, 0x5b, 0x81, 0xcf, 0x5b, 0x72, 0x2a, 0x5e, 0x86, 0x38, 0xeb, 0x6b, 0xe4, 0x87, 0x40, 0x0f, 0x3a, 0xec, 0x00, 0x6e, 0x7c]);
    }
}

#[cfg(test)]
mod tests_sha384 {
    use super::*;

    #[test]
    fn test_abc() {
        let mut sha384 = SHA384::new(&());

        let data = "abc".as_bytes();

        sha384.update(&data);

        let res = sha384.finalise();
        assert_eq!(res, [0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b, 0xb5, 0xa0, 0x3d, 0x69, 0x9a, 0xc6, 0x50, 0x07, 0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63, 0x1a, 0x8b, 0x60, 0x5a, 0x43, 0xff, 0x5b, 0xed, 0x80, 0x86, 0x07, 0x2b, 0xa1, 0xe7, 0xcc, 0x23, 0x58, 0xba, 0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7]);
    }

    #[test]
    fn test_padding_two_blocs() {
        let mut sha384 = SHA384::new(&());

        let data = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".as_bytes();

        sha384.update(&data);

        let res = sha384.finalise();
        assert_eq!(res, [0x33, 0x91, 0xfd, 0xdd, 0xfc, 0x8d, 0xc7, 0x39, 0x37, 0x07, 0xa6, 0x5b, 0x1b, 0x47, 0x09, 0x39, 0x7c, 0xf8, 0xb1, 0xd1, 0x62, 0xaf, 0x05, 0xab, 0xfe, 0x8f, 0x45, 0x0d, 0xe5, 0xf3, 0x6b, 0xc6, 0xb0, 0x45, 0x5a, 0x85, 0x20, 0xbc, 0x4e, 0x6f, 0x5f, 0xe9, 0x5b, 0x1f, 0xe3, 0xc8, 0x45, 0x2b]);
    }

    #[test]
    fn test_big() {
        let mut sha384 = SHA384::new(&());

        let data = "12345678901234567890123456789012345678901234567890123456789012345678901234567890".as_bytes();

        sha384.update(&data);

        let res = sha384.finalise();
        assert_eq!(res, [0xb1, 0x29, 0x32, 0xb0, 0x62, 0x7d, 0x1c, 0x06, 0x09, 0x42, 0xf5, 0x44, 0x77, 0x64, 0x15, 0x56, 0x55, 0xbd, 0x4d, 0xa0, 0xc9, 0xaf, 0xa6, 0xdd, 0x9b, 0x9e, 0xf5, 0x31, 0x29, 0xaf, 0x1b, 0x8f, 0xb0, 0x19, 0x59, 0x96, 0xd2, 0xde, 0x9c, 0xa0, 0xdf, 0x9d, 0x82, 0x1f, 0xfe, 0xe6, 0x70, 0x26]);
    }

    #[test]
    fn test_big_splitted() {
        let mut sha384 = SHA384::new(&());

        let data1 = "1234567".as_bytes();
        let data2 = "890123456789012345678".as_bytes();
        let data3 = "901234567890123456789012345678901234567890123456".as_bytes();
        let data4 = "7890".as_bytes();

        sha384.update(data1);
        sha384.update(data2);
        sha384.update(data3);
        sha384.update(data4);

        let res = sha384.finalise();
        assert_eq!(res, [0xb1, 0x29, 0x32, 0xb0, 0x62, 0x7d, 0x1c, 0x06, 0x09, 0x42, 0xf5, 0x44, 0x77, 0x64, 0x15, 0x56, 0x55, 0xbd, 0x4d, 0xa0, 0xc9, 0xaf, 0xa6, 0xdd, 0x9b, 0x9e, 0xf5, 0x31, 0x29, 0xaf, 0x1b, 0x8f, 0xb0, 0x19, 0x59, 0x96, 0xd2, 0xde, 0x9c, 0xa0, 0xdf, 0x9d, 0x82, 0x1f, 0xfe, 0xe6, 0x70, 0x26]);
    }

    #[test]
    fn test_bigbig() {
        let mut sha384 = SHA384::new(&());

        let data = "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890".as_bytes();

        sha384.update(&data);

        let res = sha384.finalise();
        assert_eq!(res, [0x3c, 0x90, 0xd9, 0xea, 0x7b, 0x4e, 0xb7, 0x19, 0xc2, 0x66, 0x05, 0x02, 0xce, 0x20, 0x29, 0x49, 0x93, 0x8d, 0xdd, 0x65, 0x38, 0xcc, 0x93, 0xbd, 0x4f, 0x98, 0xad, 0x7e, 0x60, 0xa9, 0x26, 0xed, 0x7c, 0xbc, 0xb7, 0x3e, 0x33, 0x0b, 0x1a, 0x72, 0xab, 0x78, 0xc7, 0x21, 0xda, 0x63, 0x46, 0xd4]);
    }
}

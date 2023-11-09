//! Definition of DES

use crate::symetric::block_ciphers::common::BlockCipher;
use crate::utils::xor_arrays;

pub struct DES {}

type StateDES = [u8; 64];
type SemiStateDES = [u8; 32];

fn byte_array_to_bit_array<const BYTE_COUNT: usize, const BIT_COUNT: usize>(bytes: &[u8; BYTE_COUNT]) -> [u8; BIT_COUNT] {
    let mut ret = [0; BIT_COUNT];

    for i in 0..BIT_COUNT {
        ret[i] = bytes[i/8] >> (7 - i % 8) & 1;
    }

    ret
}

fn bit_array_to_byte_array<const BYTE_COUNT: usize, const BIT_COUNT: usize>(bits: &[u8; BIT_COUNT]) -> [u8; BYTE_COUNT] {
    let mut ret = [0; BYTE_COUNT];

    for i in 0..BIT_COUNT {
        ret[i/8] |= bits[i] << (7 - i % 8);
    }

    ret
}

const IP : [usize;64] =
[58, 50, 42, 34, 26, 18, 10, 2,
60, 52, 44, 36, 28, 20, 12, 4,
62, 54, 46, 38, 30, 22, 14, 6,
64, 56, 48, 40, 32, 24, 16, 8,
57, 49, 41, 33, 25, 17,  9, 1,
59, 51, 43, 35, 27, 19, 11, 3,
61, 53, 45, 37, 29, 21, 13, 5,
63, 55, 47, 39, 31, 23, 15, 7];

const IP_INV : [usize; 64] =
[40,  8, 48, 16, 56, 24, 64, 32,
39,  7, 47, 15, 55, 23, 63, 31,
38,  6, 46, 14, 54, 22, 62, 30,
37,  5, 45, 13, 53, 21, 61, 29,
36,  4, 44, 12, 52, 20, 60, 28,
35,  3, 43, 11, 51, 19, 59, 27,
34,  2, 42, 10, 50, 18, 58, 26,
33,  1, 41,  9, 49, 17, 57, 25];

const E : [usize; 48] =
[32,  1,  2,  3,  4,  5,
4,  5,  6,  7,  8,  9,
8,  9, 10, 11, 12, 13,
12, 13, 14, 15, 16, 17,
16, 17, 18, 19, 20, 21,
20, 21, 22, 23, 24, 25,
24, 25, 26, 27, 28, 29,
28, 29, 30, 31, 32,  1];

const S: [[usize; 64];8] =
[[14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13],

[15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9],

[10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12],

[7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14],

[2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3],

[12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13],

[4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12],

[13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11]];

const P : [usize; 32] =
[16,  7, 20, 21,
29, 12, 28, 17,
1, 15, 23, 26,
5, 18, 31, 10,
2,  8, 24, 14,
32, 27,  3,  9,
19, 13, 30,  6,
22, 11,  4, 25];

const PC1 : [usize; 56] =
[57, 49,  41, 33,  25,  17,  9,
1, 58,  50, 42,  34,  26, 18,
10,  2,  59, 51,  43,  35, 27,
19, 11,   3, 60,  52,  44, 36,
63, 55,  47, 39,  31,  23, 15,
7, 62,  54, 46,  38,  30, 22,
14,  6,  61, 53,  45,  37, 29,
21, 13,   5, 28,  20,  12,  4];

const PC2 : [usize; 48] =
[14, 17, 11, 24,  1,  5,
3, 28, 15,  6, 21, 10,
23, 19, 12,  4, 26,  8,
16,  7, 27, 20, 13,  2,
41, 52, 31, 37, 47, 55,
30, 40, 51, 45, 33, 48,
44, 49, 39, 56, 34, 53,
46, 42, 50, 36, 29, 32];

const LEFT_SHIFTS : [usize; 16] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

fn initial_permutation(state: &mut StateDES) {
    let mut tmp : StateDES = [0; 64];
    for i in 0..64 {
        tmp[i] = state[IP[i]-1];
    }
    *state = tmp;
}

fn inv_initial_permutation(state: &mut StateDES) {
    let mut tmp : StateDES = [0; 64];
    for i in 0..64 {
        tmp[i] = state[IP_INV[i]-1];
    }
    *state = tmp;
}

fn key_permutation_1(k: &[u8;64]) -> [u8; 56] {
    let mut tmp = [0; 56];
    for i in 0..56 {
        tmp[i] = k[PC1[i]-1];
    }
    tmp
}

fn key_permutation_2(cd: &[u8;56]) -> [u8; 48] {
    let mut tmp = [0; 48];
    for i in 0..48 {
        tmp[i] = cd[PC2[i]-1];
    }
    tmp
}

fn function_e(r: &SemiStateDES) -> [u8; 48] {
    let mut ret  = [0; 48];
    for i in 0..48 {
        ret[i] = r[E[i]-1];
    }
    ret
}

fn function_p(a: &SemiStateDES) -> [u8; 32] {
    let mut ret  = [0; 32];
    for i in 0..32 {
        ret[i] = a[P[i]-1];
    }
    ret
}


fn key_expansion(key: &[u8; 8]) -> [[u8; 48]; 16] {
    let mut subkeys = [[0; 48]; 16];

    // get the 56 useful bits
    let bit_array : [u8; 64] = byte_array_to_bit_array(key);

    // Permuted Choice 1
    let state_key = key_permutation_1(&bit_array);

    // get C and D
    let mut c : [u8; 28] = state_key[0..28].try_into().unwrap();
    let mut d : [u8; 28] = state_key[28..56].try_into().unwrap();

    // compute Kn
    for i in 0..16 {
        c.rotate_left(LEFT_SHIFTS[i]);
        d.rotate_left(LEFT_SHIFTS[i]);
        // concat C and D
        let mut tmp = [0;56];
        for i in 0..28 {
            tmp[i] = c[i];
            tmp[i+28] = d[i];
        }
        subkeys[i] = key_permutation_2(&tmp);
    }

    subkeys
}

fn function_f(r: &SemiStateDES, k: &[u8; 48]) -> SemiStateDES {
    let e_res = function_e(r);
    let xored = xor_arrays(&e_res, k);
    let mut s_res = [0; 32];
    for i in 0..8 {
        let start_idx = i * 6;
        let row = xored[start_idx] << 1 | xored[start_idx+5];
        let col = xored[start_idx+1] << 3 | xored[start_idx+2] << 2 | xored[start_idx+3] << 1 | xored[start_idx+4];
        let tmp = S[i][(row * 16 + col) as usize];
        s_res[i*4] = ((tmp >> 3) & 1) as u8;
        s_res[i*4+1] = ((tmp >> 2) & 1) as u8;
        s_res[i*4+2] = ((tmp >> 1) & 1) as u8;
        s_res[i*4+3] = (tmp & 1) as u8;
    }

    function_p(&s_res)
}


/// Serves as encrypt AND as decrypt function. The choice is made by setting the expanded key in normal or inverted.
fn generic_des(input: &[u8;8], output: &mut [u8; 8], expanded_key: &[[u8; 48]; 16]) -> Result<(), &'static str> {
    let mut state = byte_array_to_bit_array(input);

    // initial permutation
    initial_permutation(&mut state);

    // separation in L and R blocks
    let mut l_block : SemiStateDES = state[0..32].try_into().unwrap();
    let mut r_block : SemiStateDES = state[32..64].try_into().unwrap();

    // rounds
    for round in 0..16 {
        let tmp_l = r_block;
        let tmp_r = xor_arrays(&l_block, &function_f(&r_block, &expanded_key[round]));
        l_block = tmp_l;
        r_block = tmp_r;
    }

    // final permutation
    for i in 0..32 {
        state[i] = r_block[i];
        state[i+32] = l_block[i];
    }
    inv_initial_permutation(&mut state);

    *output = bit_array_to_byte_array(&state);
    return Ok(());
}

impl BlockCipher for DES{
    const KEY_SIZE: usize = 8;
    const BLOCK_SIZE: usize = 8;

    fn cipher(plaintext: &[u8; Self::BLOCK_SIZE], ciphertext: &mut [u8;Self::BLOCK_SIZE], key: &[u8; Self::KEY_SIZE]) -> Result<(), &'static str> {
        let expanded_key = key_expansion(key);
        return generic_des(plaintext, ciphertext, &expanded_key);
    }

    fn decipher(plaintext: &mut [u8;Self::BLOCK_SIZE], ciphertext: &[u8;Self::BLOCK_SIZE], key: &[u8; Self::KEY_SIZE]) -> Result<(), &'static str> {
        let mut expanded_key = key_expansion(key);
        expanded_key.reverse();
        return generic_des(ciphertext, plaintext, &expanded_key);
    }
}


#[cfg(test)]
mod tests_des {
    use super::*;

    #[test]
    fn des_encrypt() {
        // cf. https://page.math.tu-berlin.de/~kant/teaching/hess/krypto-ws2006/des.htm
        let plain = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let key = [0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1];
        let mut ciphertext = [0; 8];
        let expected = [0x85, 0xE8, 0x13, 0x54, 0x0F, 0x0A, 0xB4, 0x05];
        DES::cipher(&plain, &mut ciphertext, &key).expect("Error during DES execution");
        assert_eq!(ciphertext, expected);
    }

    #[test]
    fn des_decrypt() {
        let mut plain = [0; 8];
        let key = [0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1];
        let ciphertext = [0x85, 0xE8, 0x13, 0x54, 0x0F, 0x0A, 0xB4, 0x05];
        let expected = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        DES::decipher(&mut plain, &ciphertext, &key).expect("Error during DES execution");
        assert_eq!(plain, expected);
    }
}

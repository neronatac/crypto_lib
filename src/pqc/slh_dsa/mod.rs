//! Stateless Hash-based Digital Signature Algorithm
//! Cf. FIPS 205

use crate::hash::common::Hash;
use crate::hash::mgf1::mgf1;
use crate::hash::sha::{SHA256, SHA512};
use crate::mac::common::MAC;
use crate::mac::hmac::HMAC;
use crate::pqc::slh_dsa::adrs::{AdrsC, AdrsTrait};
use crate::pqc::slh_dsa::slh_dsa::SLHDSA;

mod adrs;
mod fors;
mod hypertree;
pub mod slh_dsa;
mod utils;
mod wotsplus;
mod xmss;

// variants definitions
impl SLHDSA<16, 7, 9, 12, 14, 63, AdrsC> {
    // short variant, category 1, SHA2
    pub fn sha2_128s() -> Self {
        SLHDSA::new(
            f_sha2_cat1,
            prf_sha2_cat1,
            t_sha2_cat1,
            h_sha2_cat1,
            prg_msg_sha2_cat1,
            hmsg_sha2_cat1::<30>,
        )
    }
}

impl SLHDSA<16, 22, 3, 6, 33, 66, AdrsC> {
    // fast variant, category 1, SHA2
    pub fn sha2_128f() -> Self {
        SLHDSA::new(
            f_sha2_cat1,
            prf_sha2_cat1,
            t_sha2_cat1,
            h_sha2_cat1,
            prg_msg_sha2_cat1,
            hmsg_sha2_cat1::<34>,
        )
    }
}

impl SLHDSA<24, 7, 9, 14, 17, 63, AdrsC> {
    // short variant, category 3, SHA2
    pub fn sha2_192s() -> Self {
        SLHDSA::new(
            f_sha2_cat3_5::<24>,
            prf_sha2_cat3_5::<24>,
            t_sha2_cat3_5::<24>,
            h_sha2_cat3_5::<24>,
            prg_msg_sha2_ca3_51::<24>,
            hmsg_sha2_cat3_5::<39, 24>,
        )
    }
}

impl SLHDSA<24, 22, 3, 8, 33, 66, AdrsC> {
    // fast variant, category 3, SHA2
    pub fn sha2_192f() -> Self {
        SLHDSA::new(
            f_sha2_cat3_5::<24>,
            prf_sha2_cat3_5::<24>,
            t_sha2_cat3_5::<24>,
            h_sha2_cat3_5::<24>,
            prg_msg_sha2_ca3_51::<24>,
            hmsg_sha2_cat3_5::<42, 24>,
        )
    }
}

impl SLHDSA<32, 8, 8, 14, 22, 64, AdrsC> {
    // short variant, category 5, SHA2
    pub fn sha2_256s() -> Self {
        SLHDSA::new(
            f_sha2_cat3_5::<32>,
            prf_sha2_cat3_5::<32>,
            t_sha2_cat3_5::<32>,
            h_sha2_cat3_5::<32>,
            prg_msg_sha2_ca3_51::<32>,
            hmsg_sha2_cat3_5::<47, 32>,
        )
    }
}

impl SLHDSA<32, 17, 4, 9, 35, 68, AdrsC> {
    // fast variant, category 5, SHA2
    pub fn sha2_256f() -> Self {
        SLHDSA::new(
            f_sha2_cat3_5::<32>,
            prf_sha2_cat3_5::<32>,
            t_sha2_cat3_5::<32>,
            h_sha2_cat3_5::<32>,
            prg_msg_sha2_ca3_51::<32>,
            hmsg_sha2_cat3_5::<49, 32>,
        )
    }
}

// SHA2 - Security Category 1: n = 16
fn hmsg_sha2_cat1<const M: usize>(
    r: &[u8; 16],
    pk_seed: &[u8; 16],
    pk_root: &[u8; 16],
    m: &[u8],
) -> Vec<u8> {
    let mut hash = SHA256::new(&());
    hash.update(r);
    hash.update(pk_seed);
    hash.update(pk_root);
    hash.update(m);
    let tmp = hash.finalise();

    let mut concat = Vec::with_capacity(16 + 16 + 32);
    concat.extend_from_slice(r);
    concat.extend_from_slice(pk_seed);
    concat.extend_from_slice(&tmp);

    mgf1::<SHA256, 32>(&concat, M)
}

fn prf_sha2_cat1(pk_seed: &[u8; 16], sk_seed: &[u8; 16], adrs: &AdrsC) -> [u8; 16] {
    let mut hash = SHA256::new(&());
    hash.update(pk_seed);
    hash.update(&[0; 64 - 16]);
    hash.update(&adrs.as_bytes());
    hash.update(sk_seed);
    let res = hash.finalise();
    res[0..16].try_into().unwrap()
}

fn prg_msg_sha2_cat1(sk_prf: &[u8; 16], opt_rand: &[u8; 16], m: &[u8]) -> [u8; 16] {
    let mut data = Vec::with_capacity(16 + m.len());
    data.extend_from_slice(opt_rand);
    data.extend_from_slice(m);
    let res = HMAC::<SHA256>::compute(&data, sk_prf.to_vec());
    res[0..16].try_into().unwrap()
}

fn f_sha2_cat1(pk_seed: &[u8; 16], adrs: &AdrsC, m: &[u8; 16]) -> [u8; 16] {
    let mut hash = SHA256::new(&());
    hash.update(pk_seed);
    hash.update(&[0; 64 - 16]);
    hash.update(&adrs.as_bytes());
    hash.update(m);
    let res = hash.finalise();
    res[0..16].try_into().unwrap()
}

fn h_sha2_cat1(pk_seed: &[u8; 16], adrs: &AdrsC, m: &[u8]) -> [u8; 16] {
    let mut hash = SHA256::new(&());
    hash.update(pk_seed);
    hash.update(&[0; 64 - 16]);
    hash.update(&adrs.as_bytes());
    hash.update(m);
    let res = hash.finalise();
    res[0..16].try_into().unwrap()
}

use h_sha2_cat1 as t_sha2_cat1;

// SHA2 - Security Category 3 and 5: n = 24 or 32
fn hmsg_sha2_cat3_5<const M: usize, const N: usize>(
    r: &[u8; N],
    pk_seed: &[u8; N],
    pk_root: &[u8; N],
    m: &[u8],
) -> Vec<u8> {
    let mut hash = SHA512::new(&());
    hash.update(r);
    hash.update(pk_seed);
    hash.update(pk_root);
    hash.update(m);
    let tmp = hash.finalise();

    let mut concat = Vec::with_capacity(N + N + 64);
    concat.extend_from_slice(r);
    concat.extend_from_slice(pk_seed);
    concat.extend_from_slice(&tmp);

    mgf1::<SHA512, 64>(&concat, M)
}

fn prf_sha2_cat3_5<const N: usize>(pk_seed: &[u8; N], sk_seed: &[u8; N], adrs: &AdrsC) -> [u8; N] {
    let mut hash = SHA256::new(&());
    hash.update(pk_seed);
    hash.update(&vec![0; 64 - N]);
    hash.update(&adrs.as_bytes());
    hash.update(sk_seed);
    let res = hash.finalise();
    res[0..N].try_into().unwrap()
}

fn prg_msg_sha2_ca3_51<const N: usize>(sk_prf: &[u8; N], opt_rand: &[u8; N], m: &[u8]) -> [u8; N] {
    let mut data = Vec::with_capacity(N + m.len());
    data.extend_from_slice(opt_rand);
    data.extend_from_slice(m);
    let res = HMAC::<SHA512>::compute(&data, sk_prf.to_vec());
    res[0..N].try_into().unwrap()
}

fn f_sha2_cat3_5<const N: usize>(pk_seed: &[u8; N], adrs: &AdrsC, m: &[u8; N]) -> [u8; N] {
    let mut hash = SHA256::new(&());
    hash.update(pk_seed);
    hash.update(&vec![0; 64 - N]);
    hash.update(&adrs.as_bytes());
    hash.update(m);
    let res = hash.finalise();
    res[0..N].try_into().unwrap()
}

fn h_sha2_cat3_5<const N: usize>(pk_seed: &[u8; N], adrs: &AdrsC, m: &[u8]) -> [u8; N] {
    let mut hash = SHA512::new(&());
    hash.update(pk_seed);
    hash.update(&vec![0; 128 - N]);
    hash.update(&adrs.as_bytes());
    hash.update(m);
    let res = hash.finalise();
    res[0..N].try_into().unwrap()
}

use h_sha2_cat3_5 as t_sha2_cat3_5;

#[cfg(test)]
mod tests_slhdsa_keygen {
    use super::*;

    #[test]
    fn test_sha2_128s() {
        let slh = SLHDSA::sha2_128s();

        let (res_sk, res_pk) = slh.keygen_internal(
            &[
                0x17, 0x3D, 0x04, 0xC9, 0x38, 0xC1, 0xC3, 0x6B, 0xF2, 0x89, 0xC3, 0xC0, 0x22, 0xD0,
                0x4B, 0x14,
            ],
            &[
                0x63, 0xAE, 0x23, 0xC4, 0x1A, 0xA5, 0x46, 0xDA, 0x58, 0x97, 0x74, 0xAC, 0x20, 0xB7,
                0x45, 0xC4,
            ],
            &[
                0x0D, 0x79, 0x47, 0x77, 0x91, 0x4C, 0x99, 0x76, 0x68, 0x27, 0xF0, 0xF0, 0x9C, 0xA9,
                0x72, 0xBE,
            ],
        );
        assert_eq!(
            res_sk.as_bytes(),
            [
                0x17, 0x3D, 0x04, 0xC9, 0x38, 0xC1, 0xC3, 0x6B, 0xF2, 0x89, 0xC3, 0xC0, 0x22, 0xD0,
                0x4B, 0x14, 0x63, 0xAE, 0x23, 0xC4, 0x1A, 0xA5, 0x46, 0xDA, 0x58, 0x97, 0x74, 0xAC,
                0x20, 0xB7, 0x45, 0xC4, 0x0D, 0x79, 0x47, 0x77, 0x91, 0x4C, 0x99, 0x76, 0x68, 0x27,
                0xF0, 0xF0, 0x9C, 0xA9, 0x72, 0xBE, 0x01, 0x62, 0xC1, 0x02, 0x19, 0xD4, 0x22, 0xAD,
                0xBA, 0x13, 0x59, 0xE6, 0xAA, 0x65, 0x29, 0x9C
            ]
        );
        assert_eq!(
            res_pk.as_bytes(),
            [
                0x0D, 0x79, 0x47, 0x77, 0x91, 0x4C, 0x99, 0x76, 0x68, 0x27, 0xF0, 0xF0, 0x9C, 0xA9,
                0x72, 0xBE, 0x01, 0x62, 0xC1, 0x02, 0x19, 0xD4, 0x22, 0xAD, 0xBA, 0x13, 0x59, 0xE6,
                0xAA, 0x65, 0x29, 0x9C
            ]
        );
    }
}

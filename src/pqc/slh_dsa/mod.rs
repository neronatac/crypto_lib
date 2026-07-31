//! Stateless Hash-based Digital Signature Algorithm
//! Cf. FIPS 205

use crate::hash::common::Hash;
use crate::hash::mgf1::mgf1;
use crate::hash::sha::SHA256;
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
    // short variant, category 1
    pub fn sha256_128s() -> Self {
        SLHDSA::new(
            f_sha256_cat1,
            prf_sha256_cat1,
            t_sha256_cat1,
            h_sha256_cat1,
            prg_msg_sha256_cat1,
            hmsg_sha256_cat1::<30>,
        )
    }
}

impl SLHDSA<16, 22, 3, 6, 33, 66, AdrsC> {
    // fast variant, category 1
    pub fn sha256_128f() -> Self {
        SLHDSA::new(
            f_sha256_cat1,
            prf_sha256_cat1,
            t_sha256_cat1,
            h_sha256_cat1,
            prg_msg_sha256_cat1,
            hmsg_sha256_cat1::<34>,
        )
    }
}

// SHA2 - Security Category 1: n = 16
fn hmsg_sha256_cat1<const M: usize>(
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

fn prf_sha256_cat1(pk_seed: &[u8; 16], sk_seed: &[u8; 16], adrs: &AdrsC) -> [u8; 16] {
    let mut hash = SHA256::new(&());
    hash.update(pk_seed);
    hash.update(&[0; 64 - 16]);
    hash.update(&adrs.as_bytes());
    hash.update(sk_seed);
    let res = hash.finalise();
    res[0..16].try_into().unwrap()
}

fn prg_msg_sha256_cat1(sk_prf: &[u8; 16], opt_rand: &[u8; 16], m: &[u8]) -> [u8; 16] {
    let mut data = Vec::with_capacity(16 + m.len());
    data.extend_from_slice(opt_rand);
    data.extend_from_slice(m);
    let res = HMAC::<SHA256>::compute(&data, sk_prf.to_vec());
    res[0..16].try_into().unwrap()
}

fn f_sha256_cat1(pk_seed: &[u8; 16], adrs: &AdrsC, m: &[u8; 16]) -> [u8; 16] {
    let mut hash = SHA256::new(&());
    hash.update(pk_seed);
    hash.update(&[0; 64 - 16]);
    hash.update(&adrs.as_bytes());
    hash.update(m);
    let res = hash.finalise();
    res[0..16].try_into().unwrap()
}

fn h_sha256_cat1(pk_seed: &[u8; 16], adrs: &AdrsC, m: &[u8]) -> [u8; 16] {
    let mut hash = SHA256::new(&());
    hash.update(pk_seed);
    hash.update(&[0; 64 - 16]);
    hash.update(&adrs.as_bytes());
    hash.update(m);
    let res = hash.finalise();
    res[0..16].try_into().unwrap()
}

use h_sha256_cat1 as t_sha256_cat1;

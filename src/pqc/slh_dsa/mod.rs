//! Stateless Hash-based Digital Signature Algorithm
//! Cf. FIPS 205

use crate::hash::common::Hash;
use crate::hash::sha::SHA256;
use crate::pqc::slh_dsa::slh_dsa::SLHDSA;

mod adrs;
mod fors;
mod hypertree;
mod slh_dsa;
mod utils;
mod wotsplus;
mod xmss;


// variants definitions
pub type SlhDsa128s<ADRS, F, PRF, T, HFUNC, PRFMSG, HMSG> =
    SLHDSA<16, 7, 9, 12, 14, 63, ADRS, F, PRF, T, HFUNC, PRFMSG, HMSG>;

pub type SlhDsaSha2_128s = SlhDsa128s<AdrsC, >;

// SHA2 - Security Category 1
fn hmsg_sha2_cat1<const M: usize>(r: &[u8; 16], pk_seed: &[u8; 16], pk_root: &[u8; 16], m: &[u8]) -> Vec<u8> {
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

    mgf1<SHA256>(concat, M)
}
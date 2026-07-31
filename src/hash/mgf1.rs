use crate::hash::common::Hash;

pub fn mgf1<H, const HLEN: usize>(seed: &[u8], mask_len: usize) -> Vec<u8>
where
    H: Hash<HLEN, InitStruct = ()>,
{
    if mask_len > 2usize.pow(32) {
        panic!("mask_len must be < 2^32");
    }

    let mut t = Vec::with_capacity(mask_len.div_ceil(HLEN) * HLEN);
    let mut ctr = 0u32;

    while t.len() < mask_len {
        let c = ctr.to_be_bytes();
        let mut hash = H::new(&());
        hash.update(seed);
        hash.update(&c);
        let tmp = hash.finalise();
        t.extend_from_slice(&tmp);
    }

    t[0..mask_len].to_vec()
}

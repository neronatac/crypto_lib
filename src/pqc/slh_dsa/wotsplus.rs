use crate::pqc::slh_dsa::adrs::{AdrsTrait, AdrsType};
use crate::pqc::slh_dsa::utils::{base_2b, to_byte};
use bytemuck::{cast_slice, Pod};
use std::marker::PhantomData;

pub struct WOTSPlus<const N: usize, const LGW: usize, ADRS, const TREE_ADDR_LEN: usize>
where
    ADRS: AdrsTrait<TREE_ADDR_LEN>,
    [u8; N]: Pod, // to be able to flatten Vec<[u8; N]> to [u8]
{
    // PhantomData to fakely use ADRS type constraint
    _adrs: PhantomData<ADRS>,

    // functions used by WOTS+
    f_func: fn(&[u8; N], &ADRS, &[u8; N]) -> [u8; N],
    prf_func: fn(&[u8; N], &[u8; N], &ADRS) -> [u8; N],
    t_func: fn(&[u8; N], &ADRS, &[u8]) -> [u8; N],

    // additional values derived from n and lgw
    w: usize,
    len1: usize,
    len2: usize,
    pub len: usize,
}

impl<const N: usize, ADRS, const TREE_ADDR_LEN: usize> WOTSPlus<N, 4, ADRS, TREE_ADDR_LEN>
where
    ADRS: AdrsTrait<TREE_ADDR_LEN>,
    [u8; N]: Pod,
{
    // helpers
    pub fn new(
        f_func: fn(&[u8; N], &ADRS, &[u8; N]) -> [u8; N],
        prf_func: fn(&[u8; N], &[u8; N], &ADRS) -> [u8; N],
        t_func: fn(&[u8; N], &ADRS, &[u8]) -> [u8; N],
    ) -> Self {
        let w = 2usize.pow(4u32);
        let len1 = (8f32 * N as f32 / 4f32).ceil() as usize;
        let len2 = (((len1 * (w - 1)) as f32).log2() / 4f32).floor() as usize + 1;
        let len = len1 + len2;

        WOTSPlus::<N, 4, ADRS, TREE_ADDR_LEN> {
            _adrs: PhantomData,
            f_func,
            prf_func,
            t_func,
            w,
            len1,
            len2,
            len,
        }
    }
    
    pub fn signature_from_bytes(&self, bytes: &[u8]) -> Vec::<[u8; N]> {
        let mut sig = Vec::<[u8; N]>::with_capacity(self.len);
        
        let mut idx = 0;
        for _ in 0..self.len {
            sig.push(bytes[idx..idx+N].try_into().unwrap());
            idx += N;
        }
        
        sig
    }
    
    // functions from spec
    fn chain(
        &self,
        x: &[u8; N],
        i: usize,
        s: usize,
        pk_seed: &[u8; N],
        adrs: &mut ADRS,
    ) -> [u8; N] {
        let mut tmp = *x; // copy
        for j in i..i + s {
            adrs.set_hash_address(j as u32);
            tmp = (self.f_func)(pk_seed, adrs, &tmp);
        }
        tmp
    }

    /// WOTS+ Public-Key Generation
    pub fn pk_gen(&self, sk_seed: &[u8; N], pk_seed: &[u8; N], adrs: &mut ADRS) -> [u8; N] {
        let mut sk_adrs = adrs.clone();
        sk_adrs.set_type_and_clear(AdrsType::WotsPrf);
        sk_adrs.set_key_pair_address(adrs.get_key_pair_address());

        let mut tmp = Vec::<[u8; N]>::with_capacity(self.len);
        for i in 0..self.len {
            sk_adrs.set_chain_address(i as u32);
            let sk = (self.prf_func)(pk_seed, sk_seed, &sk_adrs);
            adrs.set_chain_address(i as u32);
            tmp.push(self.chain(&sk, 0, self.w - 1, pk_seed, adrs));
        }

        let mut wots_pk_adrs = adrs.clone();
        wots_pk_adrs.set_type_and_clear(AdrsType::WotsPk);
        wots_pk_adrs.set_key_pair_address(adrs.get_key_pair_address());

        (self.t_func)(pk_seed, &wots_pk_adrs, cast_slice(&tmp))
    }

    /// WOTS+ Signature Generation
    pub fn sign(
        &self,
        m: &[u8; N],
        sk_seed: &[u8; N],
        pk_seed: &[u8; N],
        adrs: &mut ADRS,
    ) -> Vec<[u8; N]> {
        let mut sig = Vec::<[u8; N]>::with_capacity(self.len);

        let mut csum = 0;
        let mut msg = base_2b(m, 4, self.len1);

        for i in 0..self.len1 {
            csum += self.w - 1 - msg[i] as usize;
        }

        csum = csum << ((8 - (self.len2 * 4) % 8) % 8);

        let target_len = self.len2.div_ceil(2); // * 4 / 8
        let tmp_bytes = to_byte(csum, target_len);
        msg.extend(base_2b(&tmp_bytes, 4, self.len2));

        let mut sk_adrs = adrs.clone();
        sk_adrs.set_type_and_clear(AdrsType::WotsPrf);
        sk_adrs.set_key_pair_address(adrs.get_key_pair_address());

        for i in 0..self.len {
            sk_adrs.set_chain_address(i as u32);
            let sk = (self.prf_func)(pk_seed, sk_seed, &sk_adrs);
            adrs.set_chain_address(i as u32);
            sig.push(self.chain(&sk, 0, msg[i] as usize, pk_seed, adrs));
        }

        sig
    }

    /// WOTS+ Public Key From Signature
    pub fn pk_from_sig(
        &self,
        sig: Vec<[u8; N]>,
        m: &[u8; N],
        pk_seed: &[u8; N],
        adrs: &mut ADRS,
    ) -> [u8; N] {
        let mut tmp = Vec::<[u8; N]>::with_capacity(self.len);

        let mut csum = 0;
        let mut msg = base_2b(m, 4, self.len1);

        for i in 0..self.len1 {
            csum += self.w - 1 - msg[i] as usize;
        }

        csum = csum << ((8 - (self.len2 * 4) % 8) % 8);

        let target_len = self.len2.div_ceil(2); // * 4 / 8
        let tmp_bytes = to_byte(csum, target_len);
        msg.extend(base_2b(&tmp_bytes, 4, self.len2));

        for i in 0..self.len {
            adrs.set_chain_address(i as u32);
            tmp.push(self.chain(
                &sig[i],
                msg[i] as usize,
                self.w - 1 - msg[i] as usize,
                pk_seed,
                adrs,
            ));
        }

        let mut wotspk_adrs = adrs.clone();
        wotspk_adrs.set_type_and_clear(AdrsType::WotsPk);
        wotspk_adrs.set_key_pair_address(adrs.get_key_pair_address());

        (self.t_func)(pk_seed, &wotspk_adrs, cast_slice(&tmp))
    }
}

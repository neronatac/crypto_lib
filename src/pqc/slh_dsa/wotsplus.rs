use std::marker::PhantomData;
use bytemuck::{cast_slice, Pod};
use crate::pqc::slh_dsa::adrs::{AdrsTrait, AdrsType};

pub struct WOTSPlus<const N: usize, const LGW: usize, ADRS, F, PRF, T>
where
    ADRS: AdrsTrait,
    F: Fn(&[u8; N], &ADRS, &[u8; N]) -> [u8; N],
    PRF: Fn(&[u8; N], &[u8; N], &ADRS) -> [u8; N],
    T: Fn(&[u8; N], &ADRS, &[u8]) -> [u8; N], // actually 3rd param is l*n bytes long

    [u8; N]: Pod, // to be able to flatten Vec<[u8; N]> to [u8]
{
    // PhantomData to fakely use ADRS type constraint
    _adrs: PhantomData<ADRS>,

    // functions used by WOTS+
    f_func: F,
    prf_func: PRF,
    t_func: T,

    // additional values derived from n and lgw
    w: usize,
    len1: usize,
    len2: usize,
    len: usize,
}

impl<const N: usize, const LGW: usize, ADRS, F, PRF, T> WOTSPlus<N, LGW, ADRS, F, PRF, T>
where
    ADRS: AdrsTrait,
    F: Fn(&[u8; N], &ADRS, &[u8; N]) -> [u8; N],
    PRF: Fn(&[u8; N], &[u8; N], &ADRS) -> [u8; N],
    T: Fn(&[u8; N], &ADRS, &[u8]) -> [u8; N],

    [u8; N]: Pod,
{
    pub fn new(f_func: F, prf_func: PRF, t_func: T) -> Self {
        let w = 2usize.pow(LGW as u32);
        let len1 = (8f32 * N as f32 / LGW as f32).ceil() as usize;
        let len2 = (((len1 * (w -1)) as f32).log2() / LGW as f32).floor() as usize + 1;
        let len = len1 + len2;

        WOTSPlus::<N, LGW, ADRS, F, PRF, T>{
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

    fn chain(&self, x: &[u8; N], i: usize, s: usize, pk_seed: &[u8; N], adrs: &mut ADRS) -> [u8; N] {
        let tmp = *x; // copy
        for j in i..i + s {
            adrs.set_hash_address(j as u32);
            (self.f_func)(pk_seed, adrs, &tmp);
        }
        tmp
    }

    /// WOTS+ Public-Key Generation
    pub fn wots_pk_gen(self, sk_seed: &[u8; N], pk_seed: &[u8; N], adrs: &mut ADRS) -> [u8; N] {
        let mut sk_adrs = adrs.clone();
        sk_adrs.set_type_and_clear(AdrsType::WotsPrf);
        sk_adrs.set_key_pair_address(adrs.get_key_pair_address());

        let mut tmp = Vec::<[u8; N]>::with_capacity(self.len);
        for i in 0..self.len {
            sk_adrs.set_chain_address(i as u32);
            let sk = (self.prf_func)(pk_seed, sk_seed, &sk_adrs);
            adrs.set_chain_address(i as u32);
            tmp[i] = self.chain(&sk, 0, self.w - 1, pk_seed, adrs);
        }

        let mut wots_pk_adrs = adrs.clone();
        wots_pk_adrs.set_type_and_clear(AdrsType::WotsPk);
        wots_pk_adrs.set_key_pair_address(adrs.get_key_pair_address());

        (self.t_func)(pk_seed, &wots_pk_adrs, cast_slice(&tmp))
    }
}

use std::marker::PhantomData;
use crate::pqc::slh_dsa::adrs::{AdrsTrait};

pub struct WOTSPlus<const N: usize, F, ADRS>
where
    F: Fn(&[u8; N], &ADRS::AsBytesType, &[u8; N]) -> [u8; N],
    ADRS: AdrsTrait
{
    f: F,
    _adrs: PhantomData<ADRS>, // PhantomData to fakely use ADRS type constraint
}

impl<const N: usize, F, ADRS> WOTSPlus<N, F, ADRS>
where
    F: Fn(&[u8; N], &ADRS::AsBytesType, &[u8; N]) -> [u8; N],
    ADRS: AdrsTrait
{
    pub fn new(f: F) -> Self {
        WOTSPlus::<N, F, ADRS>{
            f,
            _adrs: PhantomData,
        }
    }

    fn chain(&self, x: &[u8; N], i: usize, s: usize, seed: &[u8; N], adrs: &mut ADRS) -> [u8; N] {
        let tmp = *x; // copy
        for j in i..i + s {
            adrs.set_hash_address(j as u32);
            (self.f)(seed, &adrs.as_bytes(), &tmp);
        }
        tmp
    }
}

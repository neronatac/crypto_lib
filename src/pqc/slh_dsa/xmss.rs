use std::marker::PhantomData;
use bytemuck::Pod;
use crate::pqc::slh_dsa::adrs::{AdrsTrait, AdrsType};
use crate::pqc::slh_dsa::wotsplus::WOTSPlus;

pub struct XMSS<const N: usize, ADRS, F, PRF, T, H>
where
    ADRS: AdrsTrait,

    F: Fn(&[u8; N], &ADRS, &[u8; N]) -> [u8; N],
    PRF: Fn(&[u8; N], &[u8; N], &ADRS) -> [u8; N],
    T: Fn(&[u8; N], &ADRS, &[u8]) -> [u8; N],
    H: Fn(&[u8; N], &ADRS, &[u8]) -> [u8; N], // actually 3rd param is 2*n bytes long

    [u8; N]: Pod, // required by WOTS: to be able to flatten Vec<[u8; N]> to [u8]
{
    // PhantomData to fakely use ADRS type constraint
    _adrs: PhantomData<ADRS>,

    // functions used by XMSS
    h_func: H,

    // wots structure
    wots: WOTSPlus<N, 4, ADRS, F, PRF, T>
}

impl<const N: usize, ADRS, F, PRF, T, H> XMSS<N, ADRS, F, PRF, T, H>
where
    ADRS: AdrsTrait,
    F: Fn(&[u8; N], &ADRS, &[u8; N]) -> [u8; N],
    PRF: Fn(&[u8; N], &[u8; N], &ADRS) -> [u8; N],
    T: Fn(&[u8; N], &ADRS, &[u8]) -> [u8; N],
    H: Fn(&[u8; N], &ADRS, &[u8]) -> [u8; N],
    [u8; N]: Pod,
{
    pub fn new(f_func: F, prf_func: PRF, t_func: T, h_func: H) -> Self {
        let wots = WOTSPlus::<N, 4, ADRS, F, PRF, T>::new(f_func, prf_func, t_func);

        XMSS::<N, ADRS, F, PRF, T, H> {
            _adrs: PhantomData,
            h_func,
            wots,
        }
    }

    fn node(&self, sk_seed: &[u8; N], i: u32, z: u32, pk_seed: &[u8; N], adrs: &mut ADRS) -> [u8; N] {
        if z == 0 {
            adrs.set_type_and_clear(AdrsType::WotsHash);
            adrs.set_key_pair_address(i);
            self.wots.pk_gen(sk_seed, pk_seed, adrs)
        } else {
            let lnode = self.node(sk_seed, 2 * i, z - 1, pk_seed, adrs);
            let rnode = self.node(sk_seed, 2 * i + 1, z - 1, pk_seed, adrs);
            adrs.set_type_and_clear(AdrsType::Tree);
            adrs.set_tree_height(z);
            adrs.set_tree_index(i);

            let concat = [lnode, rnode].concat();

            (self.h_func)(pk_seed, adrs, &concat)
        }
    }
}
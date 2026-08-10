use crate::pqc::slh_dsa::adrs::{AdrsTrait, AdrsType};
use crate::pqc::slh_dsa::wotsplus::WOTSPlus;
use bytemuck::Pod;
use std::marker::PhantomData;

#[derive(Clone)]
pub struct XMSSSignature<const N: usize> {
    sig_wots: Vec<[u8; N]>,
    auth: Vec<[u8; N]>,
}

impl<const N: usize> XMSSSignature<N> {
    pub fn len(&self) -> usize {
        (self.sig_wots.len() + self.auth.len()) * N
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut res = Vec::with_capacity(self.len());
        for i in self.sig_wots.iter() {
            res.extend_from_slice(i);
        }
        for i in self.auth.iter() {
            res.extend_from_slice(i);
        }
        res
    }
}

pub struct XMSS<const N: usize, const H_PRIME: usize, ADRS, const TREE_ADDR_LEN: usize>
where
    ADRS: AdrsTrait<TREE_ADDR_LEN>,
    [u8; N]: Pod, // required by WOTS: to be able to flatten Vec<[u8; N]> to [u8]
{
    // PhantomData to fakely use ADRS type constraint
    _adrs: PhantomData<ADRS>,

    // functions used by XMSS
    h_func: fn(&[u8; N], &ADRS, &[u8]) -> [u8; N],

    // wots structure
    pub wots: WOTSPlus<N, 4, ADRS, TREE_ADDR_LEN>,
}

impl<const N: usize, const H_PRIME: usize, ADRS, const TREE_ADDR_LEN: usize> XMSS<N, H_PRIME, ADRS, TREE_ADDR_LEN>
where
    ADRS: AdrsTrait<TREE_ADDR_LEN>,
    [u8; N]: Pod,
{
    // helpers
    pub fn new(
        f_func: fn(&[u8; N], &ADRS, &[u8; N]) -> [u8; N],
        prf_func: fn(&[u8; N], &[u8; N], &ADRS) -> [u8; N],
        t_func: fn(&[u8; N], &ADRS, &[u8]) -> [u8; N],
        h_func: fn(&[u8; N], &ADRS, &[u8]) -> [u8; N],
    ) -> Self {
        let wots = WOTSPlus::<N, 4, ADRS, TREE_ADDR_LEN>::new(f_func, prf_func, t_func);

        XMSS::<N, H_PRIME, ADRS, TREE_ADDR_LEN> {
            _adrs: PhantomData,
            h_func,
            wots,
        }
    }

    // import method is defined here because XMSSSignature does not know its own length
    pub fn signature_from_bytes(&self, bytes: &[u8]) -> XMSSSignature<N> {
        let sig_wots = self.wots.signature_from_bytes(bytes);
        let mut auth = Vec::<[u8; N]>::with_capacity(H_PRIME);

        let mut idx = sig_wots.len() * N;
        for _ in 0..H_PRIME {
            auth.push(bytes[idx..idx+N].try_into().unwrap());
            idx += N;
        }

        XMSSSignature { sig_wots, auth }
    }

    // functions from spec
    pub fn node(
        &self,
        sk_seed: &[u8; N],
        i: u32,
        z: u32,
        pk_seed: &[u8; N],
        adrs: &mut ADRS,
    ) -> [u8; N] {
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

    pub fn sign(
        &self,
        m: &[u8; N],
        sk_seed: &[u8; N],
        idx: u32,
        pk_seed: &[u8; N],
        adrs: &mut ADRS,
    ) -> XMSSSignature<N> {
        let mut auth = Vec::<[u8; N]>::with_capacity(H_PRIME);
        for j in 0..H_PRIME {
            let k = ((idx as f32 / 2u32.pow(j as u32) as f32).floor() as u32) ^ 1;
            auth.push(self.node(sk_seed, k, j as u32, pk_seed, adrs));
        }

        adrs.set_type_and_clear(AdrsType::WotsHash);
        adrs.set_key_pair_address(idx);

        let sig_wots = self.wots.sign(m, sk_seed, pk_seed, adrs);

        XMSSSignature { sig_wots, auth }
    }

    pub fn pk_from_sig(
        &self,
        idx: u32,
        sig_xmss: &XMSSSignature<N>,
        m: &[u8; N],
        pk_seed: &[u8; N],
        adrs: &mut ADRS,
    ) -> [u8; N] {
        adrs.set_type_and_clear(AdrsType::WotsHash);
        adrs.set_key_pair_address(idx);
        let sig = sig_xmss.sig_wots.clone();
        let auth = sig_xmss.auth.clone();

        let mut node0 = self.wots.pk_from_sig(sig, m, pk_seed, adrs);
        let mut node1;

        adrs.set_type_and_clear(AdrsType::Tree);
        adrs.set_tree_index(idx);

        for k in 0..H_PRIME {
            adrs.set_tree_height((k + 1) as u32);

            let tmp = (idx as f32 / 2u32.pow(k as u32) as f32).floor() as u32;

            if tmp % 2 == 0 {
                adrs.set_tree_index(adrs.get_tree_index() / 2);
            } else {
                adrs.set_tree_index((adrs.get_tree_index() - 1) / 2);
            }

            let concat = {
                if tmp % 2 == 0 {
                    [node0, auth[k]].concat()
                } else {
                    [auth[k], node0].concat()
                }
            };

            node1 = (self.h_func)(pk_seed, adrs, concat.as_slice());
            node0 = node1;
        }

        node0
    }
}

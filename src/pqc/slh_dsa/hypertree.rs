use crate::pqc::slh_dsa::adrs::{AdrsTrait, TreeAddress};
use crate::pqc::slh_dsa::xmss::{XMSSSignature, XMSS};
use bytemuck::Pod;
use std::marker::PhantomData;

#[derive(Clone)]
pub struct HypertreeSignature<const N: usize> {
    sigs_xmss: Vec<XMSSSignature<N>>,
}

impl<const N: usize> HypertreeSignature<N> {
    pub fn len(&self) -> usize {
        self.sigs_xmss.len() * self.sigs_xmss[0].len()
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut res = Vec::with_capacity(self.len());
        for i in self.sigs_xmss.iter() {
            res.extend_from_slice(&i.as_bytes());
        }
        res
    }
}

pub struct Hypertree<const N: usize, const D: usize, const H_PRIME: usize, ADRS, const TREE_ADDR_LEN: usize>
where
    ADRS: AdrsTrait<TREE_ADDR_LEN>,
    [u8; N]: Pod, // required by WOTS: to be able to flatten Vec<[u8; N]> to [u8]
{
    // PhantomData to fakely use ADRS type constraint
    _adrs: PhantomData<ADRS>,

    // XMSS structure
    xmss: XMSS<N, H_PRIME, ADRS, TREE_ADDR_LEN>,
}

impl<const N: usize, const D: usize, const H_PRIME: usize, ADRS, const TREE_ADDR_LEN: usize> Hypertree<N, D, H_PRIME, ADRS, TREE_ADDR_LEN>
where
    ADRS: AdrsTrait<TREE_ADDR_LEN>,
    [u8; N]: Pod,
{
    pub fn new(
        f_func: fn(&[u8; N], &ADRS, &[u8; N]) -> [u8; N],
        prf_func: fn(&[u8; N], &[u8; N], &ADRS) -> [u8; N],
        t_func: fn(&[u8; N], &ADRS, &[u8]) -> [u8; N],
        h_func: fn(&[u8; N], &ADRS, &[u8]) -> [u8; N],
    ) -> Self {
        let xmss = XMSS::<N, H_PRIME, ADRS, TREE_ADDR_LEN>::new(f_func, prf_func, t_func, h_func);

        Hypertree::<N, D, H_PRIME, ADRS, TREE_ADDR_LEN> {
            _adrs: PhantomData,
            xmss,
        }
    }

    pub fn sign(
        &self,
        m: &[u8; N],
        sk_seed: &[u8; N],
        pk_seed: &[u8; N],
        idx_tree: TreeAddress<TREE_ADDR_LEN>,
        idx_leaf: u32,
    ) -> HypertreeSignature<N> {
        let mut idx_leaf = idx_leaf;
        let mut idx_tree = idx_tree;

        let mut sigs_xmss = Vec::<XMSSSignature<N>>::with_capacity(D);

        let mut adrs = ADRS::new_null();
        adrs.set_tree_address(idx_tree);

        let mut sig_tmp = self.xmss.sign(m, sk_seed, idx_leaf, pk_seed, &mut adrs);
        sigs_xmss.push(sig_tmp.clone());

        let mut root = self
            .xmss
            .pk_from_sig(idx_leaf, &sig_tmp, m, pk_seed, &mut adrs);

        for j in 1..D {
            idx_leaf = (idx_tree % 2usize.pow(H_PRIME as u32)).value() as u32;
            idx_tree = idx_tree >> H_PRIME;

            adrs.set_layer_address(j);
            adrs.set_tree_address(idx_tree);

            sig_tmp = self.xmss.sign(&root, sk_seed, idx_leaf, pk_seed, &mut adrs);
            sigs_xmss.push(sig_tmp.clone());

            if j < D - 1 {
                root = self
                    .xmss
                    .pk_from_sig(idx_leaf, &sig_tmp, &root, pk_seed, &mut adrs);
            }
        }

        HypertreeSignature { sigs_xmss }
    }

    pub fn verify(
        &self,
        m: &[u8; N],
        sig_ht: &HypertreeSignature<N>,
        pk_seed: &[u8; N],
        idx_tree: TreeAddress<TREE_ADDR_LEN>,
        idx_leaf: u32,
        pk_root: &[u8; N],
    ) -> bool {
        let mut idx_leaf = idx_leaf;
        let mut idx_tree = idx_tree;

        let mut adrs = ADRS::new_null();
        adrs.set_tree_address(idx_tree);

        let mut node = self
            .xmss
            .pk_from_sig(idx_leaf, &sig_ht.sigs_xmss[0], m, pk_seed, &mut adrs);

        for j in 1..D {
            idx_leaf = (idx_tree % 2usize.pow(H_PRIME as u32)).value() as u32;
            idx_tree = idx_tree >> H_PRIME;

            adrs.set_layer_address(j);
            adrs.set_tree_address(idx_tree);

            node = self
                .xmss
                .pk_from_sig(idx_leaf, &sig_ht.sigs_xmss[j], &node, pk_seed, &mut adrs);
        }

        node == *pk_root
    }
}

use crate::pqc::slh_dsa::adrs::{AdrsTrait, AdrsType};
use crate::pqc::slh_dsa::utils::base_2b;
use bytemuck::checked::cast_slice;
use bytemuck::Pod;
use std::marker::PhantomData;

#[derive(Clone)]
struct FORSSignatureElement<const N: usize, const A: usize> {
    priv_key_val: [u8; N],
    auth: [[u8; N]; A],
}

impl<const N: usize, const A: usize> FORSSignatureElement<N, A> {
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut res = Vec::with_capacity(N + N * A);
        res.extend_from_slice(&self.priv_key_val);
        for i in self.auth.iter() {
            res.extend_from_slice(i);
        }
        res
    }

    pub fn from_bytes(bytes: &[u8]) -> FORSSignatureElement<N, A> {
        let priv_key_val: [u8; N] = bytes[0..N].try_into().unwrap();
        let mut auth = [[0u8; N]; A];
        let mut idx = N;
        for i in 0..A {
            auth[i] = bytes[idx..idx+N].try_into().unwrap();
            idx += N;
        }

        FORSSignatureElement { priv_key_val, auth }
    }
}

#[derive(Clone)]
pub struct FORSSignature<const N: usize, const A: usize> {
    elements: Vec<FORSSignatureElement<N, A>>,
}

impl<const N: usize, const A: usize> FORSSignature<N, A> {
    pub fn len(&self) -> usize {
        self.elements.len() * (N + A * N)
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut res = Vec::with_capacity(self.len());
        for i in self.elements.iter() {
            res.extend_from_slice(&i.as_bytes());
        }
        res
    }
}

pub struct FORS<const N: usize, const K: usize, const A: usize, ADRS, const TREE_ADDR_LEN: usize>
where
    ADRS: AdrsTrait<TREE_ADDR_LEN>,
    [u8; N]: Pod, // to be able to flatten Vec<[u8; N]> to [u8]
{
    // PhantomData to fakely use ADRS type constraint
    _adrs: PhantomData<ADRS>,

    // functions used by FORS
    f_func: fn(&[u8; N], &ADRS, &[u8; N]) -> [u8; N],
    prf_func: fn(&[u8; N], &[u8; N], &ADRS) -> [u8; N],
    t_func: fn(&[u8; N], &ADRS, &[u8]) -> [u8; N],
    h_func: fn(&[u8; N], &ADRS, &[u8]) -> [u8; N],
}

impl<const N: usize, const K: usize, const A: usize, ADRS, const TREE_ADDR_LEN: usize> FORS<N, K, A, ADRS, TREE_ADDR_LEN>
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
        FORS::<N, K, A, ADRS, TREE_ADDR_LEN> {
            _adrs: PhantomData,
            f_func,
            prf_func,
            t_func,
            h_func,
        }
    }

    // import method is defined here because FORSSignature does not know its own length (param K)
    pub fn signature_from_bytes(&self, bytes: &[u8]) -> FORSSignature<N, A> {
        let mut elements = Vec::<FORSSignatureElement<N, A>>::with_capacity(K);

        let mut idx = 0;
        for _ in 0..K {
            elements.push(FORSSignatureElement::<N, A>::from_bytes(&bytes[idx..]));
            idx += N + A * N;
        }

        FORSSignature::<N, A> {
            elements,
        }
    }

    // functions from spec
    fn sk_gen(&self, sk_seed: &[u8; N], pk_seed: &[u8; N], adrs: &ADRS, idx: u32) -> [u8; N] {
        let mut sk_adrs = adrs.clone();
        sk_adrs.set_type_and_clear(AdrsType::ForsPrf);
        sk_adrs.set_key_pair_address(adrs.get_key_pair_address());
        sk_adrs.set_tree_index(idx);
        (self.prf_func)(pk_seed, sk_seed, &sk_adrs)
    }

    fn node(
        &self,
        sk_seed: &[u8; N],
        i: u32,
        z: u32,
        pk_seed: &[u8; N],
        adrs: &mut ADRS,
    ) -> [u8; N] {
        {
            if z == 0 {
                let sk = self.sk_gen(sk_seed, pk_seed, adrs, i);
                adrs.set_tree_height(0);
                adrs.set_tree_index(i);
                (self.f_func)(pk_seed, adrs, &sk)
            } else {
                let lnode = self.node(sk_seed, 2 * i, z - 1, pk_seed, adrs);
                let rnode = self.node(sk_seed, 2 * i + 1, z - 1, pk_seed, adrs);
                adrs.set_tree_height(z);
                adrs.set_tree_index(i);
                let concat = [lnode, rnode].concat();
                (self.h_func)(pk_seed, adrs, &concat)
            }
        }
    }

    pub fn sign(
        &self,
        md: &[u8],
        sk_seed: &[u8; N],
        pk_seed: &[u8; N],
        adrs: &mut ADRS,
    ) -> FORSSignature<N, A> {
        let mut elements = Vec::<FORSSignatureElement<N, A>>::with_capacity(K);

        let indices = base_2b(md, A, K);

        for i in 0..K {
            let sk = self.sk_gen(
                sk_seed,
                pk_seed,
                adrs,
                i as u32 * 2u32.pow(A as u32) + indices[i],
            );
            let mut auth = [[0; N]; A];
            for j in 0..A {
                let s = (indices[i] as f32 / 2u32.pow(j as u32) as f32).floor() as u32 ^ 1;
                auth[j] = self.node(
                    sk_seed,
                    i as u32 * 2u32.pow((A - j) as u32) + s,
                    j as u32,
                    pk_seed,
                    adrs,
                );
            }
            elements.push(FORSSignatureElement {
                priv_key_val: sk,
                auth,
            })
        }

        FORSSignature { elements }
    }

    pub fn pk_from_sig(
        &self,
        sig: &FORSSignature<N, A>,
        md: &[u8],
        pk_seed: &[u8; N],
        adrs: &mut ADRS,
    ) -> [u8; N] {
        let indices = base_2b(md, A, K);

        let mut root = Vec::with_capacity(K);
        let mut node0;
        let mut node1;

        for i in 0..K {
            let sk = sig.elements[i].priv_key_val;
            let auth = sig.elements[i].auth;
            adrs.set_tree_height(0);
            adrs.set_tree_index(i as u32 * 2u32.pow(A as u32) + indices[i]);
            node0 = (self.f_func)(pk_seed, adrs, &sk);

            for j in 0..A {
                adrs.set_tree_height((j + 1) as u32);

                let tmp = (indices[i] as f32 / 2u32.pow(j as u32) as f32).floor() as u32;
                if tmp % 2 == 0 {
                    adrs.set_tree_index(adrs.get_tree_index() / 2);
                } else {
                    adrs.set_tree_index((adrs.get_tree_index() - 1) / 2);
                }

                let concat = {
                    if tmp % 2 == 0 {
                        [node0, auth[j]].concat()
                    } else {
                        [auth[j], node0].concat()
                    }
                };
                node1 = (self.h_func)(pk_seed, adrs, &concat);

                node0 = node1;
            }
            root.push(node0);
        }

        let mut fors_pk_adrs = adrs.clone();
        fors_pk_adrs.set_type_and_clear(AdrsType::ForsRoots);
        fors_pk_adrs.set_key_pair_address(adrs.get_key_pair_address());

        (self.t_func)(pk_seed, &mut fors_pk_adrs, cast_slice(&root))
    }
}

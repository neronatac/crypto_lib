use crate::hash::common::Hash;
use crate::pqc::slh_dsa::adrs::{AdrsTrait, AdrsType, TreeAddress};
use crate::pqc::slh_dsa::fors::{FORSSignature, FORS};
use crate::pqc::slh_dsa::hypertree::{Hypertree, HypertreeSignature};
use crate::pqc::slh_dsa::xmss::XMSS;
use bytemuck::Pod;
use rand::RngExt;
use std::marker::PhantomData;
use crate::pqc::slh_dsa::utils::to_int;

#[derive(Clone)]
pub struct SLHDSAPrivateKey<const N: usize> {
    sk_seed: [u8; N],
    sk_prf: [u8; N],
    pk_seed: [u8; N],
    pk_root: [u8; N],
}

impl<const N: usize> SLHDSAPrivateKey<N> {
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut res = Vec::with_capacity(4 * N);
        res.extend_from_slice(&self.sk_seed);
        res.extend_from_slice(&self.sk_prf);
        res.extend_from_slice(&self.pk_seed);
        res.extend_from_slice(&self.pk_root);
        res
    }

    pub fn from_bytes(bytes: &[u8]) -> SLHDSAPrivateKey<N> {
        SLHDSAPrivateKey{
            sk_seed: bytes[0..N].try_into().unwrap(),
            sk_prf: bytes[N..2*N].try_into().unwrap(),
            pk_seed: bytes[2*N..3*N].try_into().unwrap(),
            pk_root: bytes[3*N..4*N].try_into().unwrap(),
        }
    }
}

#[derive(Clone)]
pub struct SLHDSAPublicKey<const N: usize> {
    pk_seed: [u8; N],
    pk_root: [u8; N],
}

impl<const N: usize> SLHDSAPublicKey<N> {
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut res = Vec::with_capacity(2 * N);
        res.extend_from_slice(&self.pk_seed);
        res.extend_from_slice(&self.pk_root);
        res
    }

    pub fn from_bytes(bytes: &[u8]) -> SLHDSAPublicKey<N> {
        SLHDSAPublicKey{
            pk_seed: bytes[0..N].try_into().unwrap(),
            pk_root: bytes[N..2*N].try_into().unwrap(),
        }
    }
}

#[derive(Clone)]
pub struct SLHDSASignature<const N: usize, const A: usize> {
    r: [u8; N],
    sig_fors: FORSSignature<N, A>,
    sig_ht: HypertreeSignature<N>,
}

impl<const N: usize, const A: usize> SLHDSASignature<N, A> {
    pub fn len(&self) -> usize {
        N + self.sig_fors.len() + self.sig_ht.len()
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut res = Vec::with_capacity(self.len());
        res.extend_from_slice(&self.r);
        res.extend_from_slice(&self.sig_fors.as_bytes());
        res.extend_from_slice(&self.sig_ht.as_bytes());
        res
    }
}

pub struct SLHDSA<
    const N: usize,
    const D: usize,
    const H_PRIME: usize,
    const A: usize,
    const K: usize,
    const H: usize,
    ADRS,
    const TREE_ADDR_LEN: usize
> where
    ADRS: AdrsTrait<TREE_ADDR_LEN>,
    [u8; N]: Pod, // required by FORS and hypertree
{
    // PhantomData to fakely use ADRS type constraint
    _adrs: PhantomData<ADRS>,

    prf_msg_func: fn(&[u8; N], &[u8; N], &[u8]) -> [u8; N],
    h_msg_func: fn(&[u8; N], &[u8; N], &[u8; N], &[u8]) -> Vec<u8>,

    // XMSS structure
    xmss: XMSS<N, H_PRIME, ADRS, TREE_ADDR_LEN>,

    // FORS structure
    fors: FORS<N, K, A, ADRS, TREE_ADDR_LEN>,

    // hypertree structure
    ht: Hypertree<N, D, H_PRIME, ADRS, TREE_ADDR_LEN>,
}

impl<
        const N: usize,
        const D: usize,
        const H_PRIME: usize,
        const A: usize,
        const K: usize,
        const H: usize,
        ADRS,
        const TREE_ADDR_LEN: usize
    > SLHDSA<N, D, H_PRIME, A, K, H, ADRS, TREE_ADDR_LEN>
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
        prf_msg_func: fn(&[u8; N], &[u8; N], &[u8]) -> [u8; N],
        h_msg_func: fn(&[u8; N], &[u8; N], &[u8; N], &[u8]) -> Vec<u8>,
    ) -> Self {
        let xmss = XMSS::<N, H_PRIME, ADRS, TREE_ADDR_LEN>::new(f_func, prf_func, t_func, h_func);
        let fors = FORS::<N, K, A, ADRS, TREE_ADDR_LEN>::new(f_func, prf_func, t_func, h_func);
        let ht = Hypertree::<N, D, H_PRIME, ADRS, TREE_ADDR_LEN>::new(f_func, prf_func, t_func, h_func);

        SLHDSA::<N, D, H_PRIME, A, K, H, ADRS, TREE_ADDR_LEN> {
            _adrs: PhantomData,
            prf_msg_func,
            h_msg_func,
            xmss,
            fors,
            ht,
        }
    }

    pub fn signature_from_bytes(&self, bytes: &[u8]) -> SLHDSASignature<N, A> {
        let r = bytes[0..N].try_into().unwrap();
        let sig_fors = self.fors.signature_from_bytes(&bytes[N..]);
        let idx = N + sig_fors.len();
        let sig_ht = self.ht.signature_from_bytes(&bytes[idx..]);
        SLHDSASignature::<N, A> {
            r,
            sig_fors,
            sig_ht,
        }
    }

    // external functions
    pub fn keygen(&self) -> (SLHDSAPrivateKey<N>, SLHDSAPublicKey<N>) {
        let mut rng = rand::rng();
        let mut sk_seed = [0; N];
        let mut sk_prf = [0; N];
        let mut pk_seed = [0; N];

        rng.fill(&mut sk_seed);
        rng.fill(&mut sk_prf);
        rng.fill(&mut pk_seed);

        self.keygen_internal(&sk_seed, &sk_prf, &pk_seed)
    }

    pub fn sign(
        &self,
        m: &[u8],
        ctx: &[u8],
        sk: &SLHDSAPrivateKey<N>,
        deterministic: bool,
    ) -> SLHDSASignature<N, A> {
        if ctx.len() > 255 {
            panic!("context is too long (255 bytes max)");
        }

        let mut addrnd = [0; N];
        if !deterministic {
            let mut rng = rand::rng();
            rng.fill(&mut addrnd);
        }

        let mut m_prime = Vec::with_capacity(2 + ctx.len() + m.len());
        m_prime.push(0);
        m_prime.push(ctx.len() as u8);
        m_prime.extend_from_slice(ctx);
        m_prime.extend_from_slice(m);

        self.sign_internal(&m_prime, sk, deterministic, &addrnd)
    }

    pub fn hash_sign<PH, const DIGEST_SIZE: usize>(
        &self,
        m: &[u8],
        ctx: &[u8],
        ph_oid: &[u8; 11],
        sk: &SLHDSAPrivateKey<N>,
        deterministic: bool,
    ) -> SLHDSASignature<N, A>
    where
        PH: Hash<DIGEST_SIZE, InitStruct = ()>,
    {
        if ctx.len() > 255 {
            panic!("context is too long (255 bytes max)");
        }

        let mut addrnd = [0; N];
        if !deterministic {
            let mut rng = rand::rng();
            rng.fill(&mut addrnd);
        }

        let mut hash = PH::new(&());
        hash.update(m);
        let phm = hash.finalise();

        let mut m_prime = Vec::with_capacity(2 + ctx.len() + ph_oid.len() + phm.len());
        m_prime.push(1);
        m_prime.push(ctx.len() as u8);
        m_prime.extend_from_slice(ctx);
        m_prime.extend_from_slice(ph_oid);
        m_prime.extend_from_slice(&phm);

        self.sign_internal(&m_prime, sk, deterministic, &addrnd)
    }

    pub fn verify(
        &self,
        m: &[u8],
        sig: &SLHDSASignature<N, A>,
        ctx: &[u8],
        pk: &SLHDSAPublicKey<N>,
    ) -> bool {
        if ctx.len() > 255 {
            panic!("context is too long (255 bytes max)");
        }

        let mut m_prime = Vec::with_capacity(2 + ctx.len() + m.len());
        m_prime.push(0);
        m_prime.push(ctx.len() as u8);
        m_prime.extend_from_slice(ctx);
        m_prime.extend_from_slice(m);

        self.verify_internal(&m_prime, sig, pk)
    }

    pub fn hash_verify<PH, const DIGEST_SIZE: usize>(
        &self,
        m: &[u8],
        sig: &SLHDSASignature<N, A>,
        ctx: &[u8],
        ph_oid: &[u8; 11],
        pk: &SLHDSAPublicKey<N>,
    ) -> bool
    where
        PH: Hash<DIGEST_SIZE, InitStruct = ()>,
    {
        if ctx.len() > 255 {
            panic!("context is too long (255 bytes max)");
        }

        let mut hash = PH::new(&());
        hash.update(m);
        let phm = hash.finalise();

        let mut m_prime = Vec::with_capacity(2 + ctx.len() + ph_oid.len() + phm.len());
        m_prime.push(1);
        m_prime.push(ctx.len() as u8);
        m_prime.extend_from_slice(ctx);
        m_prime.extend_from_slice(ph_oid);
        m_prime.extend_from_slice(&phm);

        self.verify_internal(&m_prime, sig, pk)
    }

    // internal functions
    pub(crate) fn keygen_internal(
        &self,
        sk_seed: &[u8; N],
        sk_prf: &[u8; N],
        pk_seed: &[u8; N],
    ) -> (SLHDSAPrivateKey<N>, SLHDSAPublicKey<N>) {
        let mut adrs = ADRS::new_null();
        adrs.set_layer_address(D - 1);
        let pk_root = self
            .xmss
            .node(sk_seed, 0, H_PRIME as u32, pk_seed, &mut adrs);

        let sk = SLHDSAPrivateKey {
            sk_seed: *sk_seed,
            sk_prf: *sk_prf,
            pk_seed: *pk_seed,
            pk_root,
        };
        let pk = SLHDSAPublicKey {
            pk_seed: *pk_seed,
            pk_root,
        };

        (sk, pk)
    }

    pub(crate) fn sign_internal(
        &self,
        m: &[u8],
        sk: &SLHDSAPrivateKey<N>,
        deterministic: bool,
        addrnd: &[u8; N],
    ) -> SLHDSASignature<N, A> {
        let mut adrs = ADRS::new_null();

        let opt_rand = {
            if deterministic {
                sk.pk_seed
            } else {
                *addrnd
            }
        };

        let r = (self.prf_msg_func)(&sk.sk_prf, &opt_rand, m);

        let digest = (self.h_msg_func)(&r, &sk.pk_seed, &sk.pk_root, m);

        let (md, idx_tree, idx_leaf) = self.slice_digest(digest);

        adrs.set_tree_address(idx_tree);
        adrs.set_type_and_clear(AdrsType::ForsTree);
        adrs.set_key_pair_address(idx_leaf);

        let sig_fors = self.fors.sign(&md, &sk.sk_seed, &sk.pk_seed, &mut adrs);
        let pk_fors = self
            .fors
            .pk_from_sig(&sig_fors, &md, &sk.pk_seed, &mut adrs);
        let sig_ht = self
            .ht
            .sign(&pk_fors, &sk.sk_seed, &sk.pk_seed, idx_tree, idx_leaf);

        SLHDSASignature {
            r,
            sig_fors,
            sig_ht,
        }
    }

    fn verify_internal(
        &self,
        m: &[u8],
        sig: &SLHDSASignature<N, A>,
        pk: &SLHDSAPublicKey<N>,
    ) -> bool {
        if sig.len() != (1 + K * (1 + A) + H + D * self.xmss.wots.len) * N {
            return false;
        }

        let mut adrs = ADRS::new_null();

        let r = sig.r;

        let digest = (self.h_msg_func)(&r, &pk.pk_seed, &pk.pk_root, m);

        let (md, idx_tree, idx_leaf) = self.slice_digest(digest);

        adrs.set_tree_address(idx_tree);
        adrs.set_type_and_clear(AdrsType::ForsTree);
        adrs.set_key_pair_address(idx_leaf);

        let pk_fors = self
            .fors
            .pk_from_sig(&sig.sig_fors, &md, &pk.pk_seed, &mut adrs);

        self.ht.verify(
            &pk_fors,
            &sig.sig_ht,
            &pk.pk_seed,
            idx_tree,
            idx_leaf,
            &pk.pk_root,
        )
    }

    // helpers
    fn slice_digest(&self, digest: Vec<u8>) -> (Vec<u8>, TreeAddress<TREE_ADDR_LEN>, u32) {
        let md_idx = ((K * A) as f32 / 8f32).ceil() as usize;
        let md = &digest[0..md_idx];

        let idx_tree_idx = ((H as f32 - (H as f32 / D as f32)) / 8f32).ceil() as usize;
        let tmp_idx_tree = &digest[md_idx..md_idx + idx_tree_idx];

        let idx_leaf_idx = (H as f32 / (8 * D) as f32).ceil() as usize;
        let tmp_idx_leaf = &digest[md_idx + idx_tree_idx..md_idx + idx_tree_idx + idx_leaf_idx];

        let idx_tree = to_int(tmp_idx_tree) % 2u128.pow((H - H / D) as u32);
        let idx_leaf = to_int(tmp_idx_leaf) % 2u128.pow((H / D) as u32);

        (md.to_vec(), TreeAddress::<TREE_ADDR_LEN>::new(idx_tree), idx_leaf as u32)
    }
}

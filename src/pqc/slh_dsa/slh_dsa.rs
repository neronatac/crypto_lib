use crate::hash::common::Hash;
use crate::pqc::slh_dsa::adrs::{AdrsTrait, AdrsType};
use crate::pqc::slh_dsa::fors::{FORSSignature, FORS};
use crate::pqc::slh_dsa::hypertree::{Hypertree, HypertreeSignature};
use crate::pqc::slh_dsa::xmss::XMSS;
use bytemuck::Pod;
use rand::RngExt;
use std::marker::PhantomData;

#[derive(Clone)]
pub struct SLHDSAPrivateKey<const N: usize> {
    sk_seed: [u8; N],
    sk_prf: [u8; N],
    pk_seed: [u8; N],
    pk_root: [u8; N],
}

#[derive(Clone)]
pub struct SLHDSAPublicKey<const N: usize> {
    pk_seed: [u8; N],
    pk_root: [u8; N],
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
}

pub struct SLHDSA<
    const N: usize,
    const D: usize,
    const H_PRIME: usize,
    const A: usize,
    const K: usize,
    const H: usize,
    ADRS,
    F,
    PRF,
    T,
    HFUNC,
    PRFMSG,
    HMSG,
> where
    ADRS: AdrsTrait,

    F: Fn(&[u8; N], &ADRS, &[u8; N]) -> [u8; N] + Copy,
    PRF: Fn(&[u8; N], &[u8; N], &ADRS) -> [u8; N] + Copy,
    T: Fn(&[u8; N], &ADRS, &[u8]) -> [u8; N] + Copy,
    HFUNC: Fn(&[u8; N], &ADRS, &[u8]) -> [u8; N] + Copy, // actually 3rd param is 2*n bytes long
    PRFMSG: Fn(&[u8; N], &[u8; N], &[u8]) -> [u8; N] + Copy,
    HMSG: Fn(&[u8; N], &[u8; N], &[u8; N], &[u8]) -> Vec<u8> + Copy,

    [u8; N]: Pod, // required by FORS and hypertree
{
    // PhantomData to fakely use ADRS type constraint
    _adrs: PhantomData<ADRS>,

    // functions used by FORS
    f_func: F,
    prf_func: PRF,
    t_func: T,
    h_func: HFUNC,
    prf_msg_func: PRFMSG,
    h_msg_func: HMSG,

    // XMSS structure
    xmss: XMSS<N, H_PRIME, ADRS, F, PRF, T, HFUNC>,

    // FORS structure
    fors: FORS<N, K, A, ADRS, F, PRF, T, HFUNC>,

    // hypertree structure
    ht: Hypertree<N, D, H_PRIME, ADRS, F, PRF, T, HFUNC>,
}

impl<
        const N: usize,
        const D: usize,
        const H_PRIME: usize,
        const A: usize,
        const K: usize,
        const H: usize,
        ADRS,
        F,
        PRF,
        T,
        HFUNC,
        PRFMSG,
        HMSG,
    > SLHDSA<N, D, H_PRIME, A, K, H, ADRS, F, PRF, T, HFUNC, PRFMSG, HMSG>
where
    ADRS: AdrsTrait,

    F: Fn(&[u8; N], &ADRS, &[u8; N]) -> [u8; N] + Copy,
    PRF: Fn(&[u8; N], &[u8; N], &ADRS) -> [u8; N] + Copy,
    T: Fn(&[u8; N], &ADRS, &[u8]) -> [u8; N] + Copy,
    HFUNC: Fn(&[u8; N], &ADRS, &[u8]) -> [u8; N] + Copy,
    PRFMSG: Fn(&[u8; N], &[u8; N], &[u8]) -> [u8; N] + Copy,
    HMSG: Fn(&[u8; N], &[u8; N], &[u8; N], &[u8]) -> Vec<u8> + Copy,

    [u8; N]: Pod,
{
    pub fn new(
        f_func: F,
        prf_func: PRF,
        t_func: T,
        h_func: HFUNC,
        prf_msg_func: PRFMSG,
        h_msg_func: HMSG,
    ) -> Self {
        let xmss =
            XMSS::<N, H_PRIME, ADRS, F, PRF, T, HFUNC>::new(f_func, prf_func, t_func, h_func);
        let fors = FORS::<N, K, A, ADRS, F, PRF, T, HFUNC>::new(f_func, prf_func, t_func, h_func);
        let ht = Hypertree::<N, D, H_PRIME, ADRS, F, PRF, T, HFUNC>::new(
            f_func, prf_func, t_func, h_func,
        );

        SLHDSA::<N, D, H_PRIME, A, K, H, ADRS, F, PRF, T, HFUNC, PRFMSG, HMSG> {
            _adrs: PhantomData,
            f_func,
            prf_func,
            t_func,
            h_func,
            prf_msg_func,
            h_msg_func,
            xmss,
            fors,
            ht,
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
    fn keygen_internal(
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

    fn sign_internal(
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

        adrs.set_tree_address(&idx_tree.to_be_bytes());
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

        adrs.set_tree_address(&idx_tree.to_be_bytes());
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
    fn slice_digest(&self, digest: Vec<u8>) -> (Vec<u8>, u32, u32) {
        let md_idx = ((K * A) as f32 / 8f32).ceil() as usize;
        let md = &digest[0..md_idx + 1];

        let idx_tree_idx = ((H as f32 - (H as f32 / D as f32)) / 8f32).ceil() as usize;
        let tmp_idx_tree = &digest[md_idx..md_idx + idx_tree_idx + 1];

        let idx_leaf_idx = (H as f32 / (8 * D) as f32).ceil() as usize;
        let tmp_idx_leaf = &digest[md_idx + idx_tree_idx..md_idx + idx_tree_idx + idx_leaf_idx + 1];

        let idx_tree = u32::from_be_bytes(tmp_idx_tree.try_into().unwrap()) % (H - H / D) as u32;
        let idx_leaf = u32::from_be_bytes(tmp_idx_leaf.try_into().unwrap()) % (H / D) as u32;

        (md.to_vec(), idx_tree, idx_leaf)
    }
}

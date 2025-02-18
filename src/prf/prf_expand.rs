use crate::signing_key::SigningKey;
use blake2b_simd::Params;
use ark_ed_on_bls12_381::Fr;
use blake2::digest::Digest;
use blake2::Blake2s256;
use ark_ff::PrimeField;
use ark_crypto_primitives::prf::{
    Blake2s, PRF
};

const EXPAND_SEED: &[u8] = b"Zcash_ExpandSeed";
pub const IVK: &[u8] = b"Zcashivk";

pub struct PRFExpand {}
pub struct Crh {}

impl PRFExpand {
    fn calc(signing_key: SigningKey, t: &[u8]) -> [u8; 64] {
        let mut h = Params::new()
            .hash_length(64)
            .personal(EXPAND_SEED)
            .to_state();

        h.update(signing_key);
        h.update(t);
        *h.finalize().as_array()
    }

    pub fn calc_ask(signing_key: SigningKey) -> [u8; 64] {
        Self::calc(signing_key, &[0u8])
    }

    pub fn calc_nsk(signing_key: SigningKey) -> [u8; 64] {
        Self::calc(signing_key, &[1u8])
    }

    pub fn calc_ovk(signing_key: SigningKey) -> [u8; 64] {
        Self::calc(signing_key, &[2u8])
    }

    pub fn calc_default_diversified(signing_key: SigningKey, i: u8) -> [u8; 11] {
        let mut t = [0u8; 11];
        t.copy_from_slice(&Self::calc(signing_key, &[3, i]));
        t
    }
}

impl Crh {
    pub fn calc(ak: &[u8], nk: &[u8]) -> Fr {
        let mut inp: Vec<u8> = vec![];
        inp.extend(ak);
        inp.extend(nk);
        println!("hash input: {:?}", inp);

        let mut b2s = Blake2s256::new();
        b2s.update(&inp);

        let mut h = [0; 32];
        h.copy_from_slice(&b2s.finalize());
        h[31] &= 0b0000_0111;
        Fr::from_le_bytes_mod_order(&h)
    } 

    pub fn find_nullifier(nk: &[u8], rho: &[u8]) -> [u8; 32] {
        let mut inp = [0; 32];
        let mut seed = [0; 32];

        inp.copy_from_slice(nk);
        seed.copy_from_slice(rho);

        let h = Blake2s::evaluate(&inp, &seed).expect("failed");
        println!("nullifier: {:?}", h);

        h
    }
}
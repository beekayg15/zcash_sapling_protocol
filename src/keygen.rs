use ark_crypto_primitives::signature::schnorr::{self};
use ark_ec::AffineRepr;
use ark_ed_on_bls12_381::{EdwardsAffine, EdwardsProjective, Fr};
use ark_serialize::CanonicalSerialize;
use blake2::Blake2b512;
use ark_ff::PrimeField;
use rand::{distributions::Standard, rngs::StdRng, thread_rng, Rng, SeedableRng};
use ark_crypto_primitives::signature::SignatureScheme;
use std::ops::Mul;
use std::ops::Add;

use crate::{
    group_hash::{self, group_hash_h_sapling, group_hash_spend_auth}, 
    prf::prf_expand::{Crh, PRFExpand}, 
    signing_key::SigningKey
};

pub type SecretKey = schnorr::SecretKey<EdwardsProjective>;
pub type Signature = schnorr::Signature<EdwardsProjective>;
pub type OutgoingViewKey = [u8; 32];
pub type Params = schnorr::Parameters<EdwardsProjective, Blake2b512>;

#[derive(Clone, Debug)]
pub struct PublicKey(pub schnorr::PublicKey<EdwardsProjective>);

pub struct KeyChain<'a> {
    pub sk: SigningKey<'a>,
    pub ask: SecretKey,
    pub nsk: SecretKey,
    pub ovk: OutgoingViewKey,
    pub ivk: SecretKey,
    pub nk: PublicKey,
    pub params: Params,
    pub ak: PublicKey
}

impl PublicKey {
    pub fn to_repr_j(&self) -> [u8; 32] {
        let mut ser: [u8; 32] = [0; 32];
        self.0.serialize_compressed(&mut ser[..]).unwrap();
        ser
    } 
}

impl<'a> From<SigningKey<'a>> for KeyChain<'a> {
    fn from(signing_key: SigningKey<'a>) -> Self {
        let ask: SecretKey = 
            schnorr::SecretKey(Fr::from_le_bytes_mod_order(&PRFExpand::calc_ask(signing_key)));
        let nsk: SecretKey =
            schnorr::SecretKey(Fr::from_le_bytes_mod_order(&PRFExpand::calc_nsk(signing_key)));

        let mut rng = thread_rng();
        let mut parameters: Params = 
            schnorr::Schnorr::<EdwardsProjective, Blake2b512>::setup(&mut rng).unwrap();
        parameters.generator = group_hash::group_hash_spend_auth();

        let ak = PublicKey(parameters.generator.mul_bigint(ask.0.0).into());
        let nsk_fr: Fr = Fr::from_le_bytes_mod_order(&PRFExpand::calc_nsk(signing_key));
        let nk: EdwardsAffine = group_hash_h_sapling().mul_bigint(nsk_fr.0).into();
        let nk: PublicKey = PublicKey(nk);

        let mut ovk: OutgoingViewKey = [0; 32];
        ovk.copy_from_slice(&PRFExpand::calc_ovk(signing_key)[..32]);

        let ivk = schnorr::SecretKey(Crh::calc(&ak.to_repr_j(), &nk.to_repr_j()));

        KeyChain {
            sk: signing_key,
            ask: ask,
            nsk: nsk,
            ovk: ovk,
            ivk: ivk,
            nk: nk,
            params: parameters,
            ak: ak
        }
    }
}

impl<'a> KeyChain<'a> {
    pub fn get_diversified_transmission_address(&self) -> ([u8; 11], EdwardsAffine, PublicKey) {
        let mut d: [u8; 11]  = [0; 11];
        let mut gd: Option<EdwardsAffine>;
        let mut rng = thread_rng();

        loop {
            rng.fill(&mut d);
            gd = group_hash::diversify_hash(&d);
            if gd.is_some() {
                break;
            }
        }
        let gd = gd.unwrap();

        (
            d,
            gd,
            PublicKey(gd.mul(self.ivk.0).into()),
        )
    }

    pub fn get_diversified_transmission_address_from_diversifier(
        &self, 
        diversifier: &[u8; 11]
    ) -> (EdwardsAffine, EdwardsAffine) {
        let gd = group_hash::diversify_hash(diversifier).expect("Wrong Diversifier");
        let pk_d = gd.mul(self.ivk.0).into();
        (gd, pk_d)
    }

    pub fn default_diversifier(&self) -> Option<[u8; 11]> {
        for i in 0..=255_u8 {
            let d = PRFExpand::calc_default_diversified(self.sk, i);
            let gd = group_hash::diversify_hash(&d);

            if gd.is_some() {
                return Some(d);
            }
        }
        None
    }

    pub fn get_randomized_ak(&self) -> (Fr, PublicKey) {
        let rng = thread_rng();
        let alpha: Fr = StdRng::from_rng(rng).expect("Failed").sample(Standard);
        let ar = group_hash_spend_auth() .mul_bigint(alpha.0);
        let rk = self.ak.0.add(ar);

        (alpha, PublicKey(rk.into()))
    }
}

#[derive(Clone, Debug)]
pub struct ProofGenerationKey {
    pub ak: PublicKey,
    pub nsk: SecretKey,
}

impl<'a> Into<ProofGenerationKey> for KeyChain<'a> {
    fn into(self) -> ProofGenerationKey {
        ProofGenerationKey {
            ak: self.ak,
            nsk: self.nsk,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::signing_key::SigningKey;
    use ark_ff::{BigInteger, PrimeField};

    use super::KeyChain;
    const SK: SigningKey = &[
        24, 226, 141, 234, 92, 17, 129, 122, 238, 178, 26, 25, 152, 29, 40, 54, 142, 196, 56, 175,
        194, 90, 141, 185, 78, 190, 8, 215, 160, 40, 142, 9,
    ];
    const EASK: [u8; 32] = [
        14_u8, 205, 90, 238, 23, 159, 250, 205, 212, 1, 166, 13, 83, 234, 140, 55, 61, 74, 210, 17,
        50, 131, 194, 125, 63, 194, 155, 101, 185, 184, 27, 4,
    ];
    const EIVK: [u8; 32] = [
        122, 20, 109, 17, 53, 213, 214, 84, 218, 96, 59, 215, 92, 162, 179, 42, 226, 31, 203, 175, 
        125, 117, 53, 164, 86, 89, 60, 103, 25, 74, 95, 6
    ];
    #[test]
    pub fn test_kc_from_sk() {
        let sk: SigningKey = SK;
        let kc = KeyChain::from(sk);
        let eask = EASK;
        println!("ask: {:?}", kc.ask);
        println!("nsk: {:?}", kc.nsk);
        println!("ovk: {:?}", kc.ovk);
        println!("ak: {:?}", kc.ak);
        println!("nk: {:?}", kc.nk);
        println!("ivk: {:?}", kc.ivk.0.into_bigint().to_bytes_le());
        println!("params: {:?}", kc.params);
        assert_eq!(kc.ask.0.into_bigint().to_bytes_le(), eask);

        assert_eq!(EIVK.to_vec(), kc.ivk.0.into_bigint().to_bytes_le());
    }
    #[test]
    pub fn test_diversify_hash() {
        let sk: SigningKey = SK;
        let kc = KeyChain::from(sk);
        println!(
            "diversify hash: {:?}",
            kc.get_diversified_transmission_address()
        );
    }
}
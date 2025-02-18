use ark_crypto_primitives::commitment::pedersen::Randomness;
use ark_crypto_primitives::signature::{schnorr, SignatureScheme};
use ark_crypto_primitives::snark::SNARK;
use ark_ed_on_bls12_381::{EdwardsAffine, EdwardsProjective};
use ark_crypto_primitives::crh::poseidon::TwoToOneCRH;
use ark_crypto_primitives::crh::TwoToOneCRHScheme;
use ark_ff::PrimeField;
use ark_ed_on_bls12_381::{Fq, Fr};
use ark_groth16::{prepare_verifying_key, Groth16, PreparedVerifyingKey, Proof};
use ark_ff::BigInteger;
use ark_serialize::CanonicalSerialize;
use blake2::Blake2b512;
use rand::thread_rng;

use crate::circuit::Spend;
use crate::commitment::{mixing_pedersen_hash, Commitment, ValueCommitTrapdoor};
use crate::keygen::{KeyChain, PublicKey, Signature};
use crate::note::NoteValue;
use crate::prf::poseidon_config::poseidon_parameters;


#[derive(Debug, Clone)]
pub struct Nullifier(pub Fq);

impl Nullifier {
    pub fn new(note_commitment: EdwardsAffine, pos: u64, nk: EdwardsAffine) -> Self {
        let rho = mixing_pedersen_hash(
            note_commitment,
            Fr::from_le_bytes_mod_order(&pos.to_le_bytes()),
        );
        
        let val =
            <TwoToOneCRH<_> as TwoToOneCRHScheme>::evaluate(
                &poseidon_parameters(), 
                &nk.y, 
                &rho.y
            ).unwrap();
        
        Self(val)
    }
}

#[derive(Debug)]
pub struct SpendDescription {
    _cv: EdwardsAffine,
    _anchor: ark_bls12_381::Fr,
    _nf: Nullifier,
    _rk: PublicKey,
    _spend_proof: Proof<ark_bls12_381::Bls12_381>,
    _sig: Signature,
    _vk: PreparedVerifyingKey<ark_bls12_381::Bls12_381>,
}

impl SpendDescription {
    pub fn new(
        kc: KeyChain,
        merkle_path: Vec<Option<(ark_bls12_381::Fr, bool)>>,
        cv: EdwardsAffine,
        anchor: ark_bls12_381::Fr,
        nf: Nullifier,
        note_val: NoteValue,
        rcv: ValueCommitTrapdoor,
        note_com: EdwardsAffine,
        note_com_randomness: Randomness<EdwardsProjective>,
        diversifier: [u8; 11],
    ) -> Self {
        let (randomizer, randomized_ak) = kc.get_randomized_ak();
        let (gd, pk_d) = kc.get_diversified_transmission_address_from_diversifier(&diversifier);
        let note_comm_params = Commitment::setup();
        let mut pos = 0_u64;
        let mut coeff = 1;
        for &x in merkle_path.iter() {
            if let Some((_, bit)) = x {
                pos += (bit as u64) * coeff;
            }
            coeff <<= 1;
        }
        let mut oa = vec![];
        for i in randomizer.0.to_bytes_le() {
            oa.push(Some(i))
        }
        let mut nsk = vec![];
        for i in kc.nsk.0 .0.to_bytes_le() {
            nsk.push(Some(i));
        }
        let spend_circuit = Spend {
            auth_path: merkle_path.clone(),
            root: Some(anchor),
            ak: Some(kc.ak.clone().0),
            randomized_ak: Some(randomized_ak.0.clone()),
            randomness: &oa,
            sig_params: kc.params.clone(),
            nsk: &nsk,
            nk: Some(kc.nk.0.clone()),
            note_val: Some(note_val.clone()),
            rcv_old: Some(rcv.clone()),
            val_cm_old: Some(cv.into()),
            cm_params: Some(note_comm_params.clone()),
            crh_rand: Some(note_com_randomness.clone()),
            note_com: note_com.clone(),
            ivk: Some(kc.ivk.0.clone()),
            gd: Some(gd),
            pk_d: Some(pk_d),
            nf_old: Some(nf.clone()),
            pos: Some(pos),
        };
        let spend_circuit2 = Spend {
            auth_path: merkle_path,
            root: Some(anchor),
            ak: Some(kc.ak.clone().0),
            randomized_ak: Some(randomized_ak.0.clone()),
            randomness: &oa,
            sig_params: kc.params.clone(),
            nsk: &nsk,
            nk: Some(kc.nk.0.clone()),
            note_val: Some(note_val),
            rcv_old: Some(rcv),
            val_cm_old: Some(cv.into()),
            cm_params: Some(note_comm_params),
            crh_rand: Some(note_com_randomness),
            note_com: note_com,
            ivk: Some(kc.ivk.0.clone()),
            gd: Some(gd),
            pk_d: Some(pk_d),
            nf_old: Some(nf.clone()),
            pos: Some(pos),
        };
        let mut rng = thread_rng();
        
        let (pk, vk) =
            Groth16::<ark_bls12_381::Bls12_381>::circuit_specific_setup(spend_circuit2, &mut rng)
                .unwrap();
        
        let proof = Groth16::<ark_bls12_381::Bls12_381>::prove(&pk, spend_circuit, &mut rng)
            .expect("proof failed");
        let mut spend_statement = vec![];
        let mut cv_to_bytes = [0_u8; 32];
        <EdwardsAffine as CanonicalSerialize>::serialize_compressed(&cv, &mut cv_to_bytes[..])
            .unwrap();
        spend_statement.extend(cv_to_bytes);
        let sk = schnorr::SecretKey(kc.ask.0 * randomizer);
        let sig = <schnorr::Schnorr<ark_ed_on_bls12_381::EdwardsProjective,Blake2b512> as SignatureScheme>::sign(&kc.params.clone(), &sk, &spend_statement, &mut rng).expect("signature succeeded");
        let pvk = prepare_verifying_key(&vk);
        Self {
            _cv: cv,
            _anchor: anchor,
            _nf: nf,
            _rk: randomized_ak,
            _spend_proof: proof,
            _sig: sig,
            _vk: pvk,
        }
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::commitment::homomorphic_pedersen_commitment;
    use crate::keygen::KeyChain;
    use crate::pedersen_crh::Window;
    use crate::signing_key::SigningKey;
    use crate::prf::poseidon_config;
    use ark_crypto_primitives::commitment::pedersen::{
        Commitment as pdCommit, Randomness as pdRand,
    };
    use ark_crypto_primitives::commitment::CommitmentScheme;
    use ark_crypto_primitives::crh::{poseidon::TwoToOneCRH, TwoToOneCRHScheme};
    use ark_ff::UniformRand;
    use ark_std::One;
    const SK: SigningKey = &[
        24, 226, 141, 234, 92, 17, 129, 122, 238, 178, 26, 25, 152, 29, 40, 54, 142, 196, 56, 175,
        194, 90, 141, 185, 78, 190, 8, 215, 160, 40, 142, 9,
    ];
    #[test]
    pub fn test_proof_generation() {
        let kc = KeyChain::from(SK);
        let note_val = NoteValue(13);
        let (d, g_d, pk_d) = kc.get_diversified_transmission_address();
        let rcv = ValueCommitTrapdoor::random();
        let val_commitment = homomorphic_pedersen_commitment(note_val.clone(), &rcv);
        let comm = Commitment::setup();
        let crh_rand = pdRand::<EdwardsProjective>(Fr::one());
        let mut kc_key = vec![];
        kc_key.extend(kc.ak.to_repr_j());
        kc_key.extend(kc.nk.to_repr_j());
        let mut note_com_inp = vec![];
        let mut g_d_repr: [u8; 32] = [0; 32];
        <EdwardsAffine as CanonicalSerialize>::serialize_compressed(&g_d, &mut g_d_repr[..])
            .expect("failed");

        let mut pk_d_repr: [u8; 32] = [0; 32];
        <EdwardsAffine as CanonicalSerialize>::serialize_compressed(&pk_d.0, &mut pk_d_repr[..])
            .expect("failed");
        let v_repr = note_val.0.to_le_bytes();
        note_com_inp.extend(g_d_repr);
        note_com_inp.extend(pk_d_repr);
        note_com_inp.extend(v_repr);
        let note_com = pdCommit::<EdwardsProjective, Window>::commit(
            &comm.params.clone(),
            &note_com_inp,
            &crh_rand,
        )
        .expect("asdf");
        let mut ivk: [u8; 32] = [0; 32];
        ivk.copy_from_slice(&kc.ivk.0 .0.to_bytes_le());
        let mut pos: u64 = 1000;
        let mut merkle_path: Vec<Option<(ark_bls12_381::Fr, bool)>> = vec![];
        let mut root_till_now: ark_bls12_381::Fr = note_com.y;
        let mut rng = thread_rng();
        let p = pos.clone();
        for _ in 0..64 {
            let (lef, rig);
            if pos % 2 == 1 {
                lef = ark_bls12_381::Fr::rand(&mut rng);

                rig = root_till_now;
                merkle_path.push(Some((lef, true)));
            } else {
                rig = ark_bls12_381::Fr::rand(&mut rng);
                lef = root_till_now;
                merkle_path.push(Some((rig, false)));
            }
            root_till_now = <TwoToOneCRH<_> as TwoToOneCRHScheme>::evaluate(
                &poseidon_config::poseidon_parameters(),
                lef,
                rig,
            )
            .expect("hash failed");
            pos = pos / 2;
        }
        let nf = Nullifier::new(note_com, p, kc.nk.0);
        let spend_des = SpendDescription::new(
            kc,
            merkle_path,
            val_commitment,
            root_till_now,
            nf,
            note_val,
            rcv,
            note_com,
            crh_rand,
            d,
        );
        println!("generated_spend_desc : {:?}", spend_des);
    }
}

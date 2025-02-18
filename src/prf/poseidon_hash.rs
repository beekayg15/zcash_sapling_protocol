use ark_crypto_primitives::crh::poseidon::CRH;

pub type MerkleTreeHash = CRH<ark_bls12_381::Fr>;
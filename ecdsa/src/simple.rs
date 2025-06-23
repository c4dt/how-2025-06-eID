// A (hopefully) simple implementation of the ECDSA-ZKP for BBS(+) signatures to prove a signature
// against a public key stored in the Secure Element of the phone, and also in the BBS+.
//
// This implementation creates the following structures:
//
// - WalletDevice - contains secret/public key (should be encapsulated as 'signer' only), BLS12-381 representation
// of public key
// - Setup - for common, public, values, like the commitment bases and the BulletProof setup
// - SignatureProof

use ark_bls12_381::{
    Bls12_381, Fr as BlsFr, G1Affine as BlsG1Affine, G2Affine as BlsG2Affine, g1, g2,
};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, Field, PrimeField};
use ark_secp256r1::Fq;
use ark_secp256r1::{
    Affine as SecP256Affine, Config as SecP256Config, Fr as SecP256Fr, G_GENERATOR_X, G_GENERATOR_Y,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    UniformRand,
    rand::{SeedableRng, rngs::StdRng},
};
use ark_std::{io::Write, ops::Neg, rand::RngCore, vec::Vec};
use bbs_plus::prelude::{SignatureG1, SignatureG2};
use bbs_plus::proof::{PoKOfSignatureG1Proof, PoKOfSignatureG1Protocol};
use bbs_plus::setup::{KeypairG2, PublicKeyG2, SignatureParamsG1};
use blake2::Blake2b512;
use bulletproofs_plus_plus::prelude::SetupParams as BppSetupParams;
use dock_crypto_utils::transcript::{Transcript, new_merlin_transcript};
use dock_crypto_utils::{
    commitment::PedersenCommitmentKey, randomized_mult_checker::RandomizedMultChecker,
};
use equality_across_groups::{
    ec::commitments::from_base_field_to_scalar_field, eq_across_groups::ProofLargeWitness,
};
use equality_across_groups::{
    ec::{
        commitments::{CommitmentWithOpening, PointCommitment, PointCommitmentWithOpening},
        sw_point_addition::{PointAdditionProof, PointAdditionProtocol},
        sw_scalar_mult::{ScalarMultiplicationProof, ScalarMultiplicationProtocol},
    },
    error::Error,
    tom256::{Affine as Tom256Affine, Config as Tom256Config, Fr as Tom256Fr},
};
use kvac::bbs_sharp::ecdsa;
use rand_core::OsRng;
use std::collections::HashMap;
use std::time::Instant;
use test_utils::statistics::statistics;

const SECP_BP: SecP256Affine = SecP256Affine::new_unchecked(G_GENERATOR_X, G_GENERATOR_Y);

pub struct Issuer {
    setup: Setup,
    keypair: KeypairG2<Bls12_381>,
}

pub struct VerifiedCredential {
    // For our example, we only have one msg_fr, which is the public key of the holder.
    // Or perhaps we have two, if we need to put the x and y coordinates of the public key.
    messages: Vec<BlsFr>,
    // Signature of the issuer on this credential.
    signature: SignatureG1<Bls12_381>,
}

pub struct Verifier {
    setup: Setup,
    certificate: PublicKeyG2<Bls12_381>,
}

pub struct MobilePhone {
    secure_element: SecureElement,
    swiyu: Option<Swiyu>,
    setup: Setup,
}

#[derive(Default)]
pub struct SecureElement {
    keys: Vec<SecP256Fr>,
}

#[derive(Default)]
pub struct Swiyu {
    key_id: usize,
    vcs: Option<VerifiedCredential>,
}

pub struct ECDSAProof {}

// Globally known public values.
#[derive(Clone)]
pub struct Setup {
    sig_params_g1: SignatureParamsG1<Bls12_381>,
    rng: StdRng,
}

impl Issuer {
    pub fn new(mut setup: Setup) -> Self {
        Self {
            keypair: KeypairG2::<Bls12_381>::generate_using_rng(
                &mut setup.rng,
                &setup.sig_params_g1,
            ),
            setup,
        }
    }

    pub fn get_certificate(&self) -> PublicKeyG2<Bls12_381> {
        self.keypair.public_key.clone()
    }

    pub fn new_credential(&mut self, _key_pub: SecP256Affine) -> VerifiedCredential {
        // TODO: convert key_pub into a BlsFr - might even need to do x and y coordinates
        let messages = vec![];
        VerifiedCredential {
            signature: SignatureG1::<Bls12_381>::new(
                &mut self.setup.rng,
                &messages,
                &self.keypair.secret_key,
                &self.setup.sig_params_g1,
            )
            .unwrap(),
            messages,
        }
    }
}

impl Verifier {
    pub fn new(setup: Setup, certificate: PublicKeyG2<Bls12_381>) -> Self {
        Self { setup, certificate }
    }

    pub fn create_message(&mut self) -> SecP256Fr {
        SecP256Fr::rand(&mut self.setup.rng)
    }

    pub fn check_proof(&self, _message: SecP256Fr, _proof: ECDSAProof) -> bool {
        false
    }
}

impl MobilePhone {
    pub fn new(setup: Setup) -> Self {
        Self {
            setup,
            secure_element: SecureElement::default(),
            swiyu: None,
        }
    }

    pub fn install_swiyu(&mut self) {
        if self.swiyu.is_some() {
            panic!("Swiyu is already installed");
        }
        self.swiyu = Some(Swiyu::default())
    }

    pub fn secure_element(&mut self) -> &mut SecureElement {
        &mut self.secure_element
    }

    pub fn swiyu(&mut self) -> &mut Swiyu {
        match self.swiyu.as_mut() {
            Some(swiyu) => swiyu,
            None => panic!("Swiyu is not yet installed"),
        }
    }
}

impl SecureElement {
    pub fn create_kp(&mut self) -> (usize, SecP256Affine) {
        let sk = SecP256Fr::rand(&mut StdRng::seed_from_u64(0u64));
        let pk = (SECP_BP * sk).into_affine();
        self.keys.push(sk);
        (self.keys.len() - 1, pk)
    }

    pub fn sign(&self, id: usize, msg: SecP256Fr) -> ecdsa::Signature {
        ecdsa::Signature::new_prehashed(&mut StdRng::seed_from_u64(0u64), msg, self.keys[id])
    }
}

impl Swiyu {
    pub fn add_vc(&mut self, key_id: usize, credential: VerifiedCredential) {
        if self.vcs.is_some() {
            panic!("Can only have one credential");
        }
        self.key_id = key_id;
        self.vcs = Some(credential);
    }

    pub fn blind_vc(&mut self) -> PoKOfSignatureG1Proof<Bls12_381> {
        todo!()
    }
}

impl Setup {
    pub fn new() -> Self {
        Self {
            sig_params_g1: SignatureParamsG1::<Bls12_381>::new::<Blake2b512>(
                "eid-demo".as_bytes(),
                1,
            ),
            rng: StdRng::seed_from_u64(0u64),
        }
    }
}

impl ECDSAProof {
    pub fn new(
        _setup: Setup,
        _presentation: PoKOfSignatureG1Proof<Bls12_381>,
        _signature: ecdsa::Signature,
    ) -> Self {
        todo!()
    }

    pub fn verify(&self) -> bool {
        todo!()
    }
}

#[cfg(test)]
mod test {
    use std::error::Error;

    use super::*;

    #[test]
    fn sign_verify_msg() -> Result<(), Box<dyn Error>> {
        // Set up parties
        let setup = Setup::new();
        let mut issuer = Issuer::new(setup.clone());
        let mut holder = MobilePhone::new(setup.clone());
        let mut verifier = Verifier::new(setup.clone(), issuer.get_certificate());

        // Install the swiyu app and add a credential
        holder.install_swiyu();
        let (key_id, key_pub) = holder.secure_element().create_kp();
        let credential = issuer.new_credential(key_pub);
        holder.swiyu().add_vc(key_id, credential);

        // Verifier requests a presentation from the holder
        let message = verifier.create_message();

        // Holder creates a blinded presentation, an ECDSA signature, and a proof.
        // This is of course all done in the Swiyu app, but here we do it step-by-step.
        let presentation = holder.swiyu().blind_vc();
        let signature = holder.secure_element().sign(key_id, message);
        let proof = ECDSAProof::new(setup, presentation, signature); // does this also need the public key?

        // Holder sends the proof to the verifier, which checks it.
        verifier.check_proof(message, proof);
        Ok(())
    }
}

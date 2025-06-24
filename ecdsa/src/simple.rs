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
use ark_ec::short_weierstrass::Affine;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInt, BigInteger, Field, PrimeField};
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
use dock_crypto_utils::elgamal::PublicKey;
use dock_crypto_utils::signature::MessageOrBlinding;
use dock_crypto_utils::transcript::{MerlinTranscript, Transcript, new_merlin_transcript};
use dock_crypto_utils::{
    commitment::PedersenCommitmentKey, randomized_mult_checker::RandomizedMultChecker,
};
use equality_across_groups::pok_ecdsa_pubkey::{
    PoKEcdsaSigCommittedPublicKey, PoKEcdsaSigCommittedPublicKeyProtocol, TransformedEcdsaSig,
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
use std::hash::Hash;
use std::mem::zeroed;
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

pub struct Swiyu {
    setup: Setup,
    key_id: Option<usize>,
    vcs: Option<VerifiedCredential>,
}

pub struct Presentation {
    proof: PoKOfSignatureG1Proof<Bls12_381>,
    revealed: HashMap<usize, BlsFr>,
    blinded: HashMap<usize, BlsFr>,
    messages: HashMap<usize, String>,
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

    pub fn new_credential(&mut self, key_pub: SecP256Affine) -> VerifiedCredential {
        let pk_x = from_base_field_to_scalar_field::<Fq, BlsFr>(key_pub.x().unwrap());
        let pk_y = from_base_field_to_scalar_field::<Fq, BlsFr>(key_pub.y().unwrap());
        let messages = vec![pk_x, pk_y];
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
        self.swiyu = Some(Swiyu::new(self.setup.clone()))
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
    pub fn new(setup: Setup) -> Self {
        Self {
            setup,
            key_id: None,
            vcs: None,
        }
    }
    pub fn add_vc(&mut self, key_id: usize, credential: VerifiedCredential) {
        if self.vcs.is_some() {
            panic!("Can only have one credential");
        }
        self.key_id = Some(key_id);
        self.vcs = Some(credential);
    }

    pub fn blinded_presentation(&mut self, _message: &SecP256Fr) -> Presentation {
        let vc = self.vcs.as_ref().expect("No credential yet!");
        // TODO: convert message to BlsFr - _message is 4 x u64, and BlsFr::from(_message.0)
        // probably fails because it's bigger than the modulus of Bls12-381.
        let message_bls = BlsFr::rand(&mut self.setup.rng);
        // TODO: add blinding here
        let zero_blinding = BlsFr::from(BigInt::zero());
        let proof = PoKOfSignatureG1Protocol::init(
            &mut self.setup.rng,
            &vc.signature,
            &self.setup.sig_params_g1,
            vec![
                MessageOrBlinding::BlindMessageWithConcreteBlinding {
                    message: &vc.messages[0],
                    blinding: zero_blinding,
                },
                MessageOrBlinding::BlindMessageWithConcreteBlinding {
                    message: &vc.messages[1],
                    blinding: zero_blinding,
                },
            ],
        )
        .unwrap()
        .gen_proof(&message_bls)
        .unwrap();
        Presentation {
            proof,
            revealed: HashMap::new(),
            blinded: HashMap::from([
                (0usize, vc.messages[0].clone()),
                (1usize, vc.messages[1].clone()),
            ]),
            messages: HashMap::new(),
        }
    }
}

// Globally known public values.
#[derive(Clone)]
pub struct Setup {
    sig_params_g1: SignatureParamsG1<Bls12_381>,
    rng: StdRng,
    bpp_setup_params: BppSetupParams<Affine<Tom256Config>>,
    comm_key_tom: PedersenCommitmentKey<Tom256Affine>,
    comm_key_secp: PedersenCommitmentKey<SecP256Affine>,
    comm_key_bls: PedersenCommitmentKey<BlsG1Affine>,
}

impl Setup {
    const WITNESS_BIT_SIZE: usize = 64;
    const CHALLENGE_BIT_SIZE: usize = 180;
    const ABORT_PARAM: usize = 8;
    const RESPONSE_BYTE_SIZE: usize = 32;
    const NUM_REPS: usize = 1;
    const NUM_CHUNKS: usize = 4;
    const BPP_BASE: u16 = 2;

    pub fn new() -> Self {
        let comm_key_tom = PedersenCommitmentKey::<Tom256Affine>::new::<Blake2b512>(b"test2");

        // Bulletproofs++ setup
        let base = Setup::BPP_BASE;
        let mut bpp_setup_params =
            BppSetupParams::<Tom256Affine>::new_for_perfect_range_proof::<Blake2b512>(
                b"test",
                base,
                Setup::WITNESS_BIT_SIZE as u16,
                Setup::NUM_CHUNKS as u32,
            );
        bpp_setup_params.G = comm_key_tom.g;
        bpp_setup_params.H_vec[0] = comm_key_tom.h;

        Self {
            sig_params_g1: SignatureParamsG1::<Bls12_381>::new::<Blake2b512>(
                "eid-demo".as_bytes(),
                2, // x and y coordinates of the holder's public key
            ),
            rng: StdRng::seed_from_u64(0u64),
            bpp_setup_params,
            comm_key_tom,
            comm_key_secp: PedersenCommitmentKey::<SecP256Affine>::new::<Blake2b512>(b"test1"),
            comm_key_bls: PedersenCommitmentKey::<BlsG1Affine>::new::<Blake2b512>(b"test3"),
        }
    }

    fn append_transcript<T: Transcript + Clone + Write>(&self, pt: &mut T) {
        pt.append(b"comm_key_secp", &self.comm_key_secp);
        pt.append(b"comm_key_tom", &self.comm_key_tom);
        pt.append(b"comm_key_bls", &self.comm_key_bls);
        pt.append(b"bpp_setup_params", &self.bpp_setup_params);
    }
}

type ProofEqDL = ProofLargeWitness<
    Tom256Affine,
    BlsG1Affine,
    { Setup::NUM_CHUNKS },
    { Setup::WITNESS_BIT_SIZE },
    { Setup::CHALLENGE_BIT_SIZE },
    { Setup::ABORT_PARAM },
    { Setup::RESPONSE_BYTE_SIZE },
    { Setup::NUM_REPS },
>;

pub struct ECDSAProof {
    proof: PoKEcdsaSigCommittedPublicKey<{ ECDSAProof::NUM_REPS_SCALAR_MULT }>,
    proof_eq_pk_x: ProofEqDL,
    proof_eq_pk_y: ProofEqDL,
}

impl ECDSAProof {
    const NUM_REPS_SCALAR_MULT: usize = 128;

    pub fn new(
        mut setup: Setup,
        holder_pub: SecP256Affine,
        presentation: Presentation,
        signature: ecdsa::Signature,
        message: SecP256Fr,
    ) -> Self {
        // Commit to ECDSA public key on Tom-256 curve
        let comm_pk =
            PointCommitmentWithOpening::new(&mut setup.rng, &holder_pub, &setup.comm_key_tom)
                .unwrap();

        // Commit to ECDSA public key on BLS12-381 curve
        let bls_comm_pk_rx = BlsFr::rand(&mut setup.rng);
        let bls_comm_pk_ry = BlsFr::rand(&mut setup.rng);
        let bls_comm_pk_x = setup
            .comm_key_bls
            .commit(&presentation.blinded[&0], &bls_comm_pk_rx);
        let bls_comm_pk_y = setup
            .comm_key_bls
            .commit(&presentation.blinded[&1], &bls_comm_pk_ry);

        let transformed_sig = TransformedEcdsaSig::new(&signature, message, holder_pub).unwrap();
        transformed_sig
            .verify_prehashed(message, holder_pub)
            .unwrap();

        let mut prover_transcript = new_merlin_transcript(b"test");
        setup.append_transcript(&mut prover_transcript);
        prover_transcript.append(b"comm_pk", &comm_pk.comm);
        prover_transcript.append(b"bls_comm_pk_x", &bls_comm_pk_x);
        prover_transcript.append(b"bls_comm_pk_y", &bls_comm_pk_y);
        prover_transcript.append(b"message", &message);

        let protocol =
            PoKEcdsaSigCommittedPublicKeyProtocol::<{ ECDSAProof::NUM_REPS_SCALAR_MULT }>::init(
                &mut setup.rng,
                transformed_sig,
                message,
                holder_pub,
                comm_pk.clone(),
                &setup.comm_key_secp,
                &setup.comm_key_tom,
            )
            .unwrap();
        protocol
            .challenge_contribution(&mut prover_transcript)
            .unwrap();
        let challenge_prover = prover_transcript.challenge_scalar(b"challenge");
        let proof = protocol.gen_proof(&challenge_prover);

        // Proof that x coordinate is same in both Tom-256 and BLS12-381 commitments
        let proof_eq_pk_x = ProofEqDL::new(
            &mut setup.rng,
            &comm_pk.x,
            comm_pk.r_x,
            bls_comm_pk_rx,
            &setup.comm_key_tom,
            &setup.comm_key_bls,
            Setup::BPP_BASE,
            setup.bpp_setup_params.clone(),
            &mut prover_transcript,
        )
        .unwrap();

        // Proof that y coordinate is same in both Tom-256 and BLS12-381 commitments
        let proof_eq_pk_y = ProofEqDL::new(
            &mut setup.rng,
            &comm_pk.y,
            comm_pk.r_y,
            bls_comm_pk_ry,
            &setup.comm_key_tom,
            &setup.comm_key_bls,
            Setup::BPP_BASE,
            setup.bpp_setup_params.clone(),
            &mut prover_transcript,
        )
        .unwrap();

        Self {
            proof,
            proof_eq_pk_x,
            proof_eq_pk_y,
        }
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
        let presentation = holder.swiyu().blinded_presentation(&message);
        let signature = holder.secure_element().sign(key_id, message);
        let proof = ECDSAProof::new(setup, key_pub,  presentation, signature, message); // does this also need the public key?

        // Holder sends the proof to the verifier, which checks it.
        verifier.check_proof(message, proof);
        Ok(())
    }
}

// A (hopefully) simple implementation of the ECDSA-ZKP for BBS(+) signatures to prove a signature
// against a public key stored in the Secure Element of the phone, and also in the BBS+.
//
// This implementation creates the following structures:
//
// - WalletDevice - contains secret/public key (should be encapsulated as 'signer' only), BLS12-381 representation
// of public key
// - Setup - for common, public, values, like the commitment bases and the BulletProof setup
// - SignatureProof

use ark_bls12_381::{Bls12_381, Fr as BlsFr, G1Affine as BlsG1Affine};
use ark_ec::short_weierstrass::Affine;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::BigInt;
use ark_secp256r1::Fq;
pub use ark_secp256r1::{Affine as SecP256Affine, Fr as SecP256Fr};
use ark_std::{
    UniformRand,
    rand::{SeedableRng, rngs::StdRng},
};
use ark_std::{io::Write, vec::Vec};
use bbs_plus::prelude::SignatureG1;
use bbs_plus::proof::{PoKOfSignatureG1Proof, PoKOfSignatureG1Protocol};
use bbs_plus::setup::{KeypairG2, PublicKeyG2, SignatureParamsG1};
use blake2::Blake2b512;
use bulletproofs_plus_plus::prelude::SetupParams as BppSetupParams;
use dock_crypto_utils::commitment::PedersenCommitmentKey;
use dock_crypto_utils::signature::MessageOrBlinding;
use dock_crypto_utils::transcript::{Transcript, new_merlin_transcript};
use equality_across_groups::ec::commitments::PointCommitment;
use equality_across_groups::pok_ecdsa_pubkey::{
    PoKEcdsaSigCommittedPublicKey, PoKEcdsaSigCommittedPublicKeyProtocol, TransformedEcdsaSig,
};
use equality_across_groups::{
    ec::commitments::PointCommitmentWithOpening,
    tom256::{Affine as Tom256Affine, Config as Tom256Config},
};
use equality_across_groups::{
    ec::commitments::from_base_field_to_scalar_field, eq_across_groups::ProofLargeWitness,
};
pub use kvac::bbs_sharp::ecdsa;
use std::collections::{BTreeMap, HashMap};

/// The [Issuer] represents here the government issuer in Swiyu, which can create new
/// credentials for the Holder ([MobilePhone]s).
/// Each new credential is bound to the public key sent by the holder.
/// An [Issuer] has a private key to sign credentials for the holders.
/// The certificate of the issuer, the public key, can be used by the [Verifier] to
/// check that a certificate has been created by the [Issuer]
pub struct Issuer {
    setup: Setup,
    keypair: KeypairG2<Bls12_381>,
}

/// A [Verifier] in this demo only has to create random messages, and then verify that the
/// [ECDSAProof] is correct.
pub struct Verifier {
    setup: Setup,
    _certificate: PublicKeyG2<Bls12_381>,
}

/// The [MobilePhone] represents a holder. It has:
///
/// - [MobilePhone::secure_element()] to manage private keys and create signatures
/// - [MobilePhone::swiyu()] as a simple representation of the Swiyu application
///
/// To use the Swiyu app, it first needs to be [MobilePhone::install_swiyu()].
pub struct MobilePhone {
    secure_element: SecureElement,
    swiyu: Option<Swiyu>,
    setup: Setup,
}

/// A [VerifiedCredential] is created by the [Issuer] and holds the public key of the
/// [MobilePhone] in a secure way.
/// TODO: also add one or two fields which can be revealed to the verifier.
pub struct VerifiedCredential {
    // For our example, we only have one msg_fr, which is the public key of the holder.
    // Or perhaps we have two, if we need to put the x and y coordinates of the public key.
    messages: Vec<BlsFr>,
    // Signature of the issuer on this credential.
    signature: SignatureG1<Bls12_381>,
}

/// The [SecureElement] is a specially hardened part of the [MobilePhone] which can create
/// keypairs. However, the private key is inaccessible to the applications. An application
/// can only request a signature from one of the private keys, but not access it directly.
/// While this makes it much more secure, it makes it also much more difficult to create
/// useful cryptographic algorithms.
#[derive(Default)]
pub struct SecureElement {
    keys: Vec<SecP256Fr>,
}

/// A simple representation of the [Swiyu] app. It needs to be set up correctly by the
/// user, which of course usually is done automatically.
/// But for our example we want to see how the public key gets transferred from the
/// [SecureElement] to the [Swiyu] app.
/// In the same way you'll have to add the [VerifiedCredential] manually.
pub struct Swiyu {
    setup: Setup,
    key_id: Option<usize>,
    vcs: Option<VerifiedCredential>,
}

/// A [Presentation] is a shortened version of the [VerifiedCredential]. It contains
/// a proof that the blinded version has been signed by the [Issuer], and can be
/// verified by the certificate of the [Issuer].
#[derive(Clone)]
pub struct Presentation {
    /// The blinded signature of the [VerifiedCredential], which can be verified
    /// using the certificate of the [Issuer].
    _proof: PoKOfSignatureG1Proof<Bls12_381>,
    /// Revealed messages of the [VerifiedCredential], which will prove that the
    /// [Presentation::_messages] are part of the credential.
    _revealed: BTreeMap<usize, BlsFr>,
    /// Blinded messages, which are usually not part of the [Presentation]. But in
    /// our example they represent a blinded version of the holder's public key.
    blinded: HashMap<usize, BlsFr>,
    /// Strings used to hash to the messages being _revealed_.
    _messages: HashMap<usize, String>,
}

/// An [ECDSAProof] links the ECDSA signature from the [SecureElement] to the [Presentation::blinded]
/// messages in zero-knowledge.
/// The commitments are randomized representations of the holder's public key.
/// The proofs link these commitments to the message to be signed, and between each other.
/// TODO: bls_comm_pk_x and bls_comm_pk_y should be in the [Presentation] instead of the
/// blinded messages. Then we must make sure that we can prove that the blinded messages
/// are actually part of the [VerifiedCredential].
#[derive(Clone)]
pub struct ECDSAProof {
    setup: Setup,
    /// The public key of the holder committed to the Tom256 curve.
    comm_pk: PointCommitment<Tom256Config>,
    /// A commitment of the x value of the public key of the holder to the BLS12-381 curve.
    bls_comm_pk_x: BlsG1Affine,
    /// A commitment of the y value of the public key of the holder to the BLS12-381 curve.
    bls_comm_pk_y: BlsG1Affine,
    /// A proof that [ECDSAProof::comm_pk] can be used to verify the `message` of the verifier.
    proof: PoKEcdsaSigCommittedPublicKey<{ ECDSAProof::NUM_REPS_SCALAR_MULT }>,
    /// A proof that the x value of the public key of the holder is the same as [ECDSAProof::bls_comm_pk_x]
    proof_eq_pk_x: ProofEqDL,
    /// A proof that the y value of the public key of the holder is the same as [ECDSAProof::bls_comm_pk_x]
    proof_eq_pk_y: ProofEqDL,
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
        Self {
            setup,
            _certificate: certificate,
        }
    }

    pub fn create_message(&mut self) -> SecP256Fr {
        SecP256Fr::rand(&mut self.setup.rng)
    }

    pub fn check_proof(&self, message: SecP256Fr, _presentation: Presentation, proof: ECDSAProof) {
        // presentation._proof.verify(
        //     &presentation._revealed,
        //     &message,
        //     self._certificate,
        //     self.setup.sig_params_g1,
        // );
        proof.verify(message);
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
    pub fn create_kp(&mut self) -> SecP256Affine {
        let sk = SecP256Fr::rand(&mut StdRng::seed_from_u64(0u64));
        let pk = (ecdsa::Signature::generator() * sk).into_affine();
        self.keys.push(sk);
        pk
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

    pub fn blinded_presentation(&mut self) -> Presentation {
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
            _proof: proof,
            _revealed: BTreeMap::new(),
            blinded: HashMap::from([
                (0usize, vc.messages[0].clone()),
                (1usize, vc.messages[1].clone()),
            ]),
            _messages: HashMap::new(),
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
        Self::append_transcript_args(
            &mut prover_transcript,
            &comm_pk.comm,
            &bls_comm_pk_x,
            &bls_comm_pk_y,
            &message,
        );

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
            setup,
            comm_pk: comm_pk.comm,
            bls_comm_pk_x,
            bls_comm_pk_y,
            proof,
            proof_eq_pk_x,
            proof_eq_pk_y,
        }
    }

    pub fn verify(&self, message: SecP256Fr) {
        let mut verifier_transcript = new_merlin_transcript(b"test");
        self.setup.append_transcript(&mut verifier_transcript);
        self.append_transcript(&mut verifier_transcript, &message);
        self.proof
            .challenge_contribution(&mut verifier_transcript)
            .unwrap();

        let challenge_verifier = verifier_transcript.challenge_scalar(b"challenge");

        // verify_using_randomized_mult_checker can be used like previous test to make it much faster.
        self.proof
            .verify(
                message,
                &self.comm_pk,
                &challenge_verifier,
                &self.setup.comm_key_secp,
                &self.setup.comm_key_tom,
            )
            .expect("ECDSA proof failed");

        self.proof_eq_pk_x
            .verify(
                &self.comm_pk.x,
                &self.bls_comm_pk_x,
                &self.setup.comm_key_tom,
                &self.setup.comm_key_bls,
                &self.setup.bpp_setup_params,
                &mut verifier_transcript,
            )
            .expect("DlEQ proof for x position failed");

        self.proof_eq_pk_y
            .verify(
                &self.comm_pk.y,
                &self.bls_comm_pk_y,
                &self.setup.comm_key_tom,
                &self.setup.comm_key_bls,
                &self.setup.bpp_setup_params,
                &mut verifier_transcript,
            )
            .expect("DlEQ proff for y position failed");
    }

    fn append_transcript<T: Transcript + Clone + Write>(&self, pt: &mut T, message: &SecP256Fr) {
        Self::append_transcript_args(
            pt,
            &self.comm_pk,
            &self.bls_comm_pk_x,
            &self.bls_comm_pk_y,
            message,
        );
    }

    fn append_transcript_args<T: Transcript + Clone + Write>(
        pt: &mut T,
        comm_pk: &PointCommitment<Tom256Config>,
        bls_comm_pk_x: &BlsG1Affine,
        bls_comm_pk_y: &BlsG1Affine,
        message: &SecP256Fr,
    ) {
        pt.append(b"comm_pk", comm_pk);
        pt.append(b"bls_comm_pk_x", bls_comm_pk_x);
        pt.append(b"bls_comm_pk_y", bls_comm_pk_y);
        pt.append(b"message", message);
    }
}

#[cfg(test)]
mod test {
    use std::{collections::BTreeMap, error::Error};

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
        let key_pub = holder.secure_element().create_kp();
        let credential = issuer.new_credential(key_pub);
        holder.swiyu().add_vc(0, credential);

        // Verifier requests a presentation from the holder
        let message = verifier.create_message();

        // Holder creates a blinded presentation, an ECDSA signature, and a proof.
        // This is of course all done in the Swiyu app, but here we do it step-by-step.
        let presentation = holder.swiyu().blinded_presentation();
        let signature = holder.secure_element().sign(0, message);
        let proof = ECDSAProof::new(setup, key_pub, presentation.clone(), signature, message);

        // Holder sends the proof to the verifier, which checks it.
        verifier.check_proof(message, presentation, proof.clone());
        Ok(())
    }

    #[test]
    fn verify_bbs() -> Result<(), Box<dyn Error>> {
        let mut setup = Setup::new();
        let keypair =
            KeypairG2::<Bls12_381>::generate_using_rng(&mut setup.rng, &setup.sig_params_g1);
        let pk_x = BlsFr::rand(&mut setup.rng);
        // let pk_y = BlsFr::rand(&mut setup.rng);
        let messages = vec![pk_x, pk_x];
        let signature = SignatureG1::<Bls12_381>::new(
            &mut setup.rng,
            &messages,
            &keypair.secret_key,
            &setup.sig_params_g1,
        )
        .unwrap();

        let challenge = BlsFr::rand(&mut setup.rng);
        let zero_blinding = BlsFr::from(BigInt::zero());
        let proof = PoKOfSignatureG1Protocol::init(
            &mut setup.rng,
            &signature,
            &setup.sig_params_g1,
            vec![
                MessageOrBlinding::RevealMessage(&pk_x),
                // MessageOrBlinding::RevealMessage(&pk_y),
                MessageOrBlinding::BlindMessageWithConcreteBlinding {
                    message: &pk_x,
                    blinding: zero_blinding,
                },
            ],
        )
        .unwrap()
        .gen_proof(&challenge)
        .unwrap();

        proof
            .verify(
                &BTreeMap::from([(0usize, pk_x)]),
                // &BTreeMap::from([(0usize, pk_x), (1usize, pk_y)]),
                &challenge,
                keypair.public_key.clone(),
                setup.sig_params_g1,
            )
            .expect("Verify proof");

        Ok(())
    }
}

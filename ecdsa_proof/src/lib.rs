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
use ark_ff::{BigInt, PrimeField};
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
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};

/// The [Issuer] represents here the government issuer in Swiyu, which can create new
/// credentials for the Holder ([MobilePhone]s).
/// Each new credential is bound to the public key sent by the holder.
/// An [Issuer] has a private key to sign credentials for the holders.
/// The certificate of the issuer, the public key, can be used by the [Verifier] to
/// check that a certificate has been created by the [Issuer]
pub struct Issuer {
    setup: PublicSetup,
    keypair: KeypairG2<Bls12_381>,
}

/// A [Verifier] in this demo only has to create random messages, and then verify that the
/// [ECDSAProof] is correct.
pub struct Verifier {
    setup: PublicSetup,
    certificate: PublicKeyG2<Bls12_381>,
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
    setup: PublicSetup,
}

/// A [VerifiedCredential] is created by the [Issuer] and holds the public key of the
/// [MobilePhone] in a secure way.
/// We suppose that the first two positions are the x and y value of the holder's
/// public key.
/// TODO: also add one or two fields which can be revealed to the verifier.
pub struct VerifiedCredential {
    // For our example, we only have one msg_fr, which is the public key of the holder.
    // Or perhaps we have two, if we need to put the x and y coordinates of the public key.
    messages: Vec<BlsFr>,
    // Signature of the issuer on this credential.
    signature: SignatureG1<Bls12_381>,
    // Contents of the messages which hold strings
    message_strings: BTreeMap<usize, String>,
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
    setup: PublicSetup,
    key_id: Option<usize>,
    vcs: Option<VerifiedCredential>,
}

/// A [Presentation] is a shortened version of the [VerifiedCredential]. It contains
/// a proof that the blinded version has been signed by the [Issuer], and can be
/// verified by the certificate of the [Issuer].
#[derive(Clone)]
pub struct BBSPresentation {
    /// The blinded signature of the [VerifiedCredential], which can be verified
    /// using the certificate of the [Issuer].
    proof: PoKOfSignatureG1Proof<Bls12_381>,
    /// Revealed messages of the [VerifiedCredential], which will prove that the
    /// [Presentation::_messages] are part of the credential.
    revealed: BTreeMap<usize, BlsFr>,
    /// Strings used to hash to the messages being _revealed_.
    _message_strings: HashMap<usize, String>,
    /// Commitments for the public keys.
    commitment_pub_x: PublicCommitment,
    commitment_pub_y: PublicCommitment,
}

/// Use an enum to show that the commitments can be open, including the random value,
/// or closed, which is secure.
#[derive(Clone)]
pub enum PublicCommitment {
    Open(BlsFr, BlsG1Affine),
    Closed(BlsG1Affine),
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
    /// The public key of the holder committed to the Tom256 curve.
    comm_pk: PointCommitment<Tom256Config>,
    /// A proof that [ECDSAProof::comm_pk] can be used to verify the `message` of the verifier.
    proof: PoKEcdsaSigCommittedPublicKey<{ ECDSAProof::NUM_REPS_SCALAR_MULT }>,
    /// A proof that the x value of the public key of the holder is the same as [ECDSAProof::bls_comm_pk_x]
    proof_eq_pk_x: ProofEqDL,
    /// A proof that the y value of the public key of the holder is the same as [ECDSAProof::bls_comm_pk_x]
    proof_eq_pk_y: ProofEqDL,
}

impl Issuer {
    pub fn new(mut setup: PublicSetup) -> Self {
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
        let (first, last) = (format!("123"), format!("456"));
        let message_strings = BTreeMap::from([
            (VerifiedCredential::FIELD_FIRSTNAME, first.clone()),
            (VerifiedCredential::FIELD_LASTNAME, last.clone()),
        ]);
        let messages = vec![
            pk_x,
            pk_y,
            (&VerifierMessage(first)).into(),
            (&VerifierMessage(last)).into(),
        ];
        VerifiedCredential {
            signature: SignatureG1::<Bls12_381>::new(
                &mut self.setup.rng,
                &messages,
                &self.keypair.secret_key,
                &self.setup.sig_params_g1,
            )
            .unwrap(),
            messages,
            message_strings,
        }
    }
}

impl VerifiedCredential {
    pub const FIELD_PUB_X: usize = 0;
    pub const FIELD_PUB_Y: usize = 1;
    pub const FIELD_FIRSTNAME: usize = 2;
    pub const FIELD_LASTNAME: usize = 3;
    pub const FIELD_COUNT: u32 = 4;

    pub fn get_message_str(&self, field: usize) -> Option<String> {
        return self.message_strings.get(&field).cloned();
    }
}

impl Verifier {
    pub fn new(setup: PublicSetup, certificate: PublicKeyG2<Bls12_381>) -> Self {
        Self { setup, certificate }
    }

    pub fn create_message(&mut self) -> VerifierMessage {
        VerifierMessage::new("Verifier")
    }

    pub fn check_proof(
        &self,
        message: &VerifierMessage,
        presentation: BBSPresentation,
        proof: ECDSAProof,
    ) {
        presentation
            .proof
            .verify(
                &presentation.revealed,
                &message.into(),
                self.certificate.clone(),
                self.setup.sig_params_g1.clone(),
            )
            .expect("Verification of BBS proof failed");
        proof.verify(self.setup.clone(), message.into(), &presentation);
    }
}

pub struct VerifierMessage(String);

impl VerifierMessage {
    pub fn new(domain: &str) -> Self {
        Self(format!(
            "{domain}: Proof request at {}",
            chrono::Utc::now().to_rfc3339()
        ))
    }

    pub fn bls_fr(&self, sub: &str) -> BlsFr {
        (&VerifierMessage(format!("{}:{sub}", self.0))).into()
    }
}

impl Into<BlsFr> for &VerifierMessage {
    fn into(self) -> BlsFr {
        let hash = Sha256::digest(self.0.as_bytes());
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash[..32]);
        BlsFr::from_le_bytes_mod_order(&bytes)
    }
}

impl Into<SecP256Fr> for &VerifierMessage {
    fn into(self) -> SecP256Fr {
        let hash = Sha256::digest(self.0.as_bytes());
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash[..32]);
        SecP256Fr::from_le_bytes_mod_order(&bytes)
    }
}

impl MobilePhone {
    pub fn new(setup: PublicSetup) -> Self {
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

    pub fn sign(&self, id: usize, msg: &VerifierMessage) -> ecdsa::Signature {
        ecdsa::Signature::new_prehashed(&mut StdRng::seed_from_u64(0u64), msg.into(), self.keys[id])
    }
}

impl Swiyu {
    pub fn new(setup: PublicSetup) -> Self {
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

    pub fn blinded_presentation(&mut self, message: &VerifierMessage) -> BBSPresentation {
        let vc = self.vcs.as_ref().expect("No credential yet!");
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
                MessageOrBlinding::BlindMessageRandomly(&vc.messages[2]),
                MessageOrBlinding::BlindMessageRandomly(&vc.messages[3]),
            ],
        )
        .unwrap()
        .gen_proof(&message.into())
        .unwrap();

        BBSPresentation {
            proof,
            revealed: BTreeMap::new(),
            _message_strings: HashMap::new(),
            commitment_pub_x: PublicCommitment::from_message(
                &mut self.setup,
                &vc.messages[VerifiedCredential::FIELD_PUB_X],
            ),
            commitment_pub_y: PublicCommitment::from_message(
                &mut self.setup,
                &vc.messages[VerifiedCredential::FIELD_PUB_Y],
            ),
        }
    }
}

impl PublicCommitment {
    pub fn from_message(setup: &mut PublicSetup, message: &BlsFr) -> Self {
        let blinding_factor = BlsFr::rand(&mut setup.rng);
        Self::Open(
            blinding_factor,
            setup.comm_key_bls.commit(message, &blinding_factor),
        )
    }

    pub fn close(self) -> Self {
        match self {
            PublicCommitment::Open(_, affine) => PublicCommitment::Closed(affine),
            _ => self,
        }
    }

    pub fn rand(&self) -> BlsFr {
        match self {
            PublicCommitment::Open(fp, _) => fp.clone(),
            _ => panic!("No random value in closed commitment"),
        }
    }

    pub fn affine(&self) -> BlsG1Affine {
        match self {
            PublicCommitment::Open(_, affine) => affine.clone(),
            PublicCommitment::Closed(affine) => affine.clone(),
        }
    }

    pub fn assert_closed(&self) {
        if let Self::Open(_, _) = self {
            panic!("PublicCommitment is open and leaks random value!");
        }
    }
}

// Globally known public values.
#[derive(Clone)]
pub struct PublicSetup {
    sig_params_g1: SignatureParamsG1<Bls12_381>,
    rng: StdRng,
    bpp_setup_params: BppSetupParams<Affine<Tom256Config>>,
    comm_key_tom: PedersenCommitmentKey<Tom256Affine>,
    comm_key_secp: PedersenCommitmentKey<SecP256Affine>,
    comm_key_bls: PedersenCommitmentKey<BlsG1Affine>,
}

impl PublicSetup {
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
        let base = PublicSetup::BPP_BASE;
        let mut bpp_setup_params =
            BppSetupParams::<Tom256Affine>::new_for_perfect_range_proof::<Blake2b512>(
                b"test",
                base,
                PublicSetup::WITNESS_BIT_SIZE as u16,
                PublicSetup::NUM_CHUNKS as u32,
            );
        bpp_setup_params.G = comm_key_tom.g;
        bpp_setup_params.H_vec[0] = comm_key_tom.h;

        Self {
            sig_params_g1: SignatureParamsG1::<Bls12_381>::new::<Blake2b512>(
                "eid-demo".as_bytes(),
                VerifiedCredential::FIELD_COUNT,
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
    { PublicSetup::NUM_CHUNKS },
    { PublicSetup::WITNESS_BIT_SIZE },
    { PublicSetup::CHALLENGE_BIT_SIZE },
    { PublicSetup::ABORT_PARAM },
    { PublicSetup::RESPONSE_BYTE_SIZE },
    { PublicSetup::NUM_REPS },
>;

impl ECDSAProof {
    const NUM_REPS_SCALAR_MULT: usize = 128;

    pub fn new(
        mut setup: PublicSetup,
        holder_pub: SecP256Affine,
        bbs_presentation: BBSPresentation,
        ecdsa_signature: ecdsa::Signature,
        verifier_message: &VerifierMessage,
    ) -> Self {
        // Commit to ECDSA public key on Tom-256 curve
        let comm_pk =
            PointCommitmentWithOpening::new(&mut setup.rng, &holder_pub, &setup.comm_key_tom)
                .unwrap();

        let transformed_sig =
            TransformedEcdsaSig::new(&ecdsa_signature, verifier_message.into(), holder_pub)
                .unwrap();
        transformed_sig
            .verify_prehashed(verifier_message.into(), holder_pub)
            .unwrap();

        let mut prover_transcript = new_merlin_transcript(b"test");
        setup.append_transcript(&mut prover_transcript);
        Self::append_transcript(
            &mut prover_transcript,
            &comm_pk.comm,
            &bbs_presentation,
            &verifier_message.into(),
        );

        let protocol =
            PoKEcdsaSigCommittedPublicKeyProtocol::<{ ECDSAProof::NUM_REPS_SCALAR_MULT }>::init(
                &mut setup.rng,
                transformed_sig,
                verifier_message.into(),
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
            bbs_presentation.commitment_pub_x.rand(),
            &setup.comm_key_tom,
            &setup.comm_key_bls,
            PublicSetup::BPP_BASE,
            setup.bpp_setup_params.clone(),
            &mut prover_transcript,
        )
        .unwrap();

        // Proof that y coordinate is same in both Tom-256 and BLS12-381 commitments
        let proof_eq_pk_y = ProofEqDL::new(
            &mut setup.rng,
            &comm_pk.y,
            comm_pk.r_y,
            bbs_presentation.commitment_pub_y.rand(),
            &setup.comm_key_tom,
            &setup.comm_key_bls,
            PublicSetup::BPP_BASE,
            setup.bpp_setup_params.clone(),
            &mut prover_transcript,
        )
        .unwrap();

        Self {
            comm_pk: comm_pk.comm,
            proof,
            proof_eq_pk_x,
            proof_eq_pk_y,
        }
    }

    pub fn verify(&self, setup: PublicSetup, message: SecP256Fr, presentation: &BBSPresentation) {
        presentation.assert_closed();
        let mut verifier_transcript = new_merlin_transcript(b"test");
        setup.append_transcript(&mut verifier_transcript);
        Self::append_transcript(
            &mut verifier_transcript,
            &self.comm_pk,
            presentation,
            &message,
        );
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
                &setup.comm_key_secp,
                &setup.comm_key_tom,
            )
            .expect("ECDSA proof failed");

        self.proof_eq_pk_x
            .verify(
                &self.comm_pk.x,
                &presentation.commitment_pub_x.affine(),
                &setup.comm_key_tom,
                &setup.comm_key_bls,
                &setup.bpp_setup_params,
                &mut verifier_transcript,
            )
            .expect("DlEQ proof for x position failed");

        self.proof_eq_pk_y
            .verify(
                &self.comm_pk.y,
                &presentation.commitment_pub_y.affine(),
                &setup.comm_key_tom,
                &setup.comm_key_bls,
                &setup.bpp_setup_params,
                &mut verifier_transcript,
            )
            .expect("DlEQ proff for y position failed");
    }

    fn append_transcript<T: Transcript + Clone + Write>(
        pt: &mut T,
        comm_pk: &PointCommitment<Tom256Config>,
        presentation: &BBSPresentation,
        message: &SecP256Fr,
    ) {
        pt.append(b"comm_pk", comm_pk);
        pt.append(b"bls_comm_pk_x", &presentation.commitment_pub_x.affine());
        pt.append(b"bls_comm_pk_y", &presentation.commitment_pub_y.affine());
        pt.append(b"message", message);
    }
}

impl BBSPresentation {
    pub fn assert_closed(&self) {
        self.commitment_pub_x.assert_closed();
        self.commitment_pub_y.assert_closed();
    }

    pub fn close(self) -> Self {
        Self {
            proof: self.proof,
            revealed: self.revealed,
            _message_strings: self._message_strings,
            commitment_pub_x: self.commitment_pub_x.close(),
            commitment_pub_y: self.commitment_pub_y.close(),
        }
    }
}
#[cfg(test)]
mod test {
    use std::{collections::BTreeMap, error::Error};

    use super::*;

    #[test]
    fn sign_verify_msg() -> Result<(), Box<dyn Error>> {
        // Set up parties
        let setup = PublicSetup::new();
        let mut issuer = Issuer::new(setup.clone());
        let mut holder = MobilePhone::new(setup.clone());
        let mut verifier = Verifier::new(setup.clone(), issuer.get_certificate());

        // Install the swiyu app and add a credential
        holder.install_swiyu();
        let key_pub = holder.secure_element().create_kp();
        let credential = issuer.new_credential(key_pub);
        holder.swiyu().add_vc(0, credential);

        // Verifier requests a presentation from the holder
        let message = &verifier.create_message();

        // Holder creates a blinded presentation, an ECDSA signature, and a proof.
        // This is of course all done in the Swiyu app, but here we do it step-by-step.
        let presentation = holder.swiyu().blinded_presentation(&message);
        let signature = holder.secure_element().sign(0, &message);
        let proof = ECDSAProof::new(setup, key_pub, presentation.clone(), signature, &message);
        let presentation_closed = presentation.close();

        // Holder sends the proof to the verifier, which checks it.
        verifier.check_proof(message, presentation_closed, proof.clone());
        Ok(())
    }

    #[test]
    fn verify_bbs() -> Result<(), Box<dyn Error>> {
        let mut setup = PublicSetup::new();
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

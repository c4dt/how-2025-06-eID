//! This is a simple implementation of the work done by Ubique using
//! ZKattest to prove that an ECDSA signature can be verified using a commitment
//! on a public key stored in a BBS credential.
//!
//! The test at the end shows how to set up a system and check that the verification
//! is correct.
//! For a longer explanation, see our [Github Repo](https://github.com/c4dt/how-2025-06-eID)
//! with Jupyter notebooks and more information.
//!
//! WARNING: This is a work of a couple of days for a hands-on workshop.
//! While the general gist of how keys are generated, signatures created and verified,
//! ZKP written and verified is correct, I'm sure that there are:
//!
//! - errors in this re-arrangement of @Lovesh's excellent work from
//! [docknetwork/crypt](https://github.com/docknetwork/crypto/blob/main/equality_across_groups/src/pok_ecdsa_pubkey.rs#L462)
//! - not optimal and not secure ways of treating private keys and other random secrets
//! - at least one glaring error in the verification of the ECDSA signature
//!
//! So while this work has been done to the best of my knowledge, I definietly took a lot
//! of shortcuts and definitely valued simplicity for a hands-on-workshop over cryptographic
//! correctness.
//!
//! May [Rogaway, Chaum and Goldwasser](https://politics.media.mit.edu/papers/Rogoway_Moral_Cryptography.pdf)
//! have mercy on me :)

use ark_bls12_381::{Bls12_381, Fr as BlsFr, G1Affine as BlsG1Affine};
use ark_ec::{AffineRepr, CurveGroup, short_weierstrass::Affine};
use ark_ff::PrimeField;
use ark_secp256r1::{Affine as SecP256Affine, Fq, Fr as SecP256Fr};
use ark_std::{
    UniformRand, Zero,
    io::Write,
    rand::{SeedableRng, rngs::StdRng},
    vec::Vec,
};
use bbs_plus::{
    error::BBSPlusError,
    prelude::SignatureG1,
    proof::{PoKOfSignatureG1Proof, PoKOfSignatureG1Protocol},
    setup::{KeypairG2, PublicKeyG2, SignatureParamsG1},
};
use blake2::Blake2b512;
use bulletproofs_plus_plus::prelude::SetupParams as BppSetupParams;
use dock_crypto_utils::{
    commitment::PedersenCommitmentKey,
    signature::MessageOrBlinding,
    transcript::{Transcript, new_merlin_transcript},
};
use equality_across_groups::{
    ec::commitments::{
        PointCommitment, PointCommitmentWithOpening, from_base_field_to_scalar_field,
    },
    eq_across_groups::ProofLargeWitness,
    pok_ecdsa_pubkey::{
        PoKEcdsaSigCommittedPublicKey, PoKEcdsaSigCommittedPublicKeyProtocol, TransformedEcdsaSig,
    },
    tom256::{Affine as Tom256Affine, Config as Tom256Config},
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
    /// Common setup.
    setup: PublicSetup,
    /// Most secret key to sign new credentials.
    keypair: KeypairG2<Bls12_381>,
}

/// A [Verifier] in this demo only has to create random messages, and then verify that the
/// [ECDSAProof] is correct.
pub struct Verifier {
    /// Common setup.
    setup: PublicSetup,
    /// Certificate of the [Issuer] - it's public key
    certificate: PublicKeyG2<Bls12_381>,
}

/// The [MobilePhone] represents a holder. It has:
///
/// - [MobilePhone::secure_element()] to manage private keys and create signatures
/// - [MobilePhone::swiyu()] as a simple representation of the Swiyu application
///
/// To use the Swiyu app, it first needs to be [MobilePhone::install_swiyu()].
pub struct MobilePhone {
    /// Common setup.
    setup: PublicSetup,
    /// Very secure and hardened element of the phone which creates keypairs, but only
    /// shares the public key. Can sign messages, but will not reveal the private key.
    secure_element: SecureElement,
    /// The wallet created by the Swiss government - of course this implementation misses
    /// a lot of functionality :)
    swiyu: Option<Swiyu>,
}

/// A [VerifiedCredential] is created by the [Issuer] and holds the public key of the
/// [MobilePhone] in a secure way.
/// We suppose that the first two positions are the x and y value of the holder's
/// public key.
/// TODO: also add one or two fields which can be revealed to the verifier.
pub struct VerifiedCredential {
    /// The messages are the values hashed to a BlsFr scalar and are secret.
    /// Only the [Issuer] and the [MobilePhone] should know them.
    /// Except for the revealed messages, of course.
    messages: Vec<BlsFr>,
    /// Signature of the issuer on this credential.
    signature: SignatureG1<Bls12_381>,
    /// Contents of the messages which hold strings
    message_strings: BTreeMap<usize, String>,
}

/// The [SecureElement] is a specially hardened part of the [MobilePhone] which can create
/// keypairs. However, the private key is inaccessible to the applications. An application
/// can only request a signature from one of the private keys, but not access it directly.
/// While this makes it much more secure, it makes it also much more difficult to create
/// useful cryptographic algorithms.
#[derive(Default)]
pub struct SecureElement {
    /// Very secure key storage - only the private keys are kept.
    /// The ID for signing directly indexes the [Vec].
    /// In a real SecureElement, the IDs are of course also tied to the
    /// applications, so application X cannot use the ID of the private key
    /// of application Y to sign something.
    keys: Vec<SecP256Fr>,
}

/// A simple representation of the [Swiyu] app. It needs to be set up correctly by the
/// user, which of course usually is done automatically.
/// But for our example we want to see how the public key gets transferred from the
/// [SecureElement] to the [Swiyu] app.
/// In the same way you'll have to add the [VerifiedCredential] manually.
pub struct Swiyu {
    /// Common Setup.
    setup: PublicSetup,
    /// The key-id of the secure element to be used in signing.
    key_id: Option<usize>,
    /// The [VerifiedCredential] received from the [Issuer].
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
    /// [BBSPresentation::message_strings] are part of the credential.
    revealed: BTreeMap<usize, BlsFr>,
    /// Strings used to hash to the messages being _revealed_.
    message_strings: HashMap<usize, String>,
    /// Commitment to the x-coordinate of the public key
    commitment_pub_x: PublicCommitment,
    /// Commitment to the y-coordinate of the public key
    commitment_pub_y: PublicCommitment,
}

/// Use an enum to show that the commitments can be open, including the random value,
/// or closed, which is secure.
#[derive(Clone)]
pub enum PublicCommitment {
    /// An Open commitment includes the random value, which is the [BlsFr] here.
    /// It should never be sent to an untrusted party, as they can unblind the
    /// value with it.
    Open(BlsFr, BlsG1Affine),
    /// A Closed commitment is stripped of its random value and can safely be shared
    /// with untrusted parties.
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
    /// A commitment of the public key of the holder to the Tom256 curve.
    comm_pk: PointCommitment<Tom256Config>,
    /// A proof that [ECDSAProof::comm_pk] can be used to verify the `message` of the verifier.
    proof: PoKEcdsaSigCommittedPublicKey<{ ECDSAProof::NUM_REPS_SCALAR_MULT }>,
    /// A proof that the x value of the public key of the holder is the same as [BBSPresentation::commitment_pub_x]
    proof_eq_pk_x: ProofEqDL,
    /// A proof that the y value of the public key of the holder is the same as [BBSPresentation::commitment_pub_y]
    proof_eq_pk_y: ProofEqDL,
}

impl Issuer {
    /// Create a new issuer with a new keypair.
    pub fn new(mut setup: PublicSetup) -> Self {
        Self {
            keypair: KeypairG2::<Bls12_381>::generate_using_rng(
                &mut setup.rng,
                &setup.sig_params_g1,
            ),
            setup,
        }
    }

    /// Returns the certificate of the [Issuer] - in this case the public key.
    pub fn get_certificate(&self) -> PublicKeyG2<Bls12_381> {
        self.keypair.public_key.clone()
    }

    /// Creates a new BBS credential using the coordinates of the holder's public key as the first two
    /// messages.
    /// The real issuer would request a proof that the holder has been authenticated and has the right
    /// to request a credential.
    /// In our case it adds a `first` and `last` to the messages.
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

/// Numbering the fields in the VerifiedCredential.
impl VerifiedCredential {
    pub const FIELD_PUB_X: usize = 0;
    pub const FIELD_PUB_Y: usize = 1;
    pub const FIELD_FIRSTNAME: usize = 2;
    pub const FIELD_LASTNAME: usize = 3;
    pub const FIELD_COUNT: u32 = 4;

    /// Reeturns the string of the given message. Only works for the first
    /// and last name. Returns `None` for the other fields.
    pub fn get_message_str(&self, field: usize) -> Option<String> {
        return self.message_strings.get(&field).cloned();
    }
}

impl Verifier {
    /// A verifier needs the certificate of the [Issuer] to know how to verify incoming
    /// [BBSPresentation]s.
    pub fn new(setup: PublicSetup, certificate: PublicKeyG2<Bls12_381>) -> Self {
        Self { setup, certificate }
    }

    /// Returns a time-based changing message which is used to avoid reply-attacks.
    pub fn create_message(&mut self) -> VerifierMessage {
        VerifierMessage::new("Verifier")
    }

    /// Checks that the given [BBSPresentation] and [ECDSAProof] correspond to the [VerifierMessage].
    /// It does the following checks:
    /// - is the [BBSPresentation] correctly signed by the [Issuer]?
    /// - does the [ECDSAProof] validate that the commitment to the public key in the [BBSPresentation]
    /// verifies the signature?
    pub fn check_proof(
        &self,
        verifier_message: &VerifierMessage,
        bbs_presentation: BBSPresentation,
        ecdsa_proof: ECDSAProof,
    ) {
        bbs_presentation
            .verify(
                self.setup.clone(),
                self.certificate.clone(),
                &verifier_message.into(),
            )
            .expect("Verification of BBS proof failed");
        ecdsa_proof.verify(
            self.setup.clone(),
            verifier_message.into(),
            &bbs_presentation,
        );
    }
}

/// The [VerifierMessage] is used both for the signature from the
/// [SecureElement] and in the [BBSPresentation].
/// This is a very simple implementation allowing to create scalars
/// for SecP256 and Bls12-381.
pub struct VerifierMessage(String);

impl VerifierMessage {
    /// Create a new message with some kind of domain separation.
    pub fn new(domain: &str) -> Self {
        Self(format!(
            "{domain}: Proof request at {}",
            chrono::Utc::now().to_rfc3339()
        ))
    }
}

/// Allow to create a Bls12-381 scalar.
impl Into<BlsFr> for &VerifierMessage {
    fn into(self) -> BlsFr {
        let hash = Sha256::digest(self.0.as_bytes());
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash[..32]);
        BlsFr::from_le_bytes_mod_order(&bytes)
    }
}

/// Allow to create a SecP256 scalar.
impl Into<SecP256Fr> for &VerifierMessage {
    fn into(self) -> SecP256Fr {
        let hash = Sha256::digest(self.0.as_bytes());
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash[..32]);
        SecP256Fr::from_le_bytes_mod_order(&bytes)
    }
}

impl MobilePhone {
    /// Creates a new mobile phone with an empty [SecureElement] and no [Swiyu] app
    /// installed.
    pub fn new(setup: PublicSetup) -> Self {
        Self {
            setup,
            secure_element: SecureElement::default(),
            swiyu: None,
        }
    }

    /// Fills in the [Swiyu] app - engineer humor...
    pub fn install_swiyu(&mut self) {
        if self.swiyu.is_some() {
            panic!("Swiyu is already installed");
        }
        self.swiyu = Some(Swiyu::new(self.setup.clone()))
    }

    /// Access the [SecureElement]. This is mostly to avoid explaining
    /// to students [Option]s and stuff.
    pub fn secure_element(&mut self) -> &mut SecureElement {
        &mut self.secure_element
    }

    /// Access the [Swiyu] app. This is mostly to avoid explaining
    /// to students [Option]s and stuff.
    /// This panics if the [Swiyu] app has not been installed.
    pub fn swiyu(&mut self) -> &mut Swiyu {
        match self.swiyu.as_mut() {
            Some(swiyu) => swiyu,
            None => panic!("Swiyu is not yet installed"),
        }
    }
}

impl SecureElement {
    /// Creates a new keypair and stores the private key in the internal [Vec].
    /// It returns the key and an id.
    pub fn create_kp(&mut self) -> SEKeypair {
        let sk = SecP256Fr::rand(&mut StdRng::seed_from_u64(0u64));
        let key_pub = (ecdsa::Signature::generator() * sk).into_affine();
        self.keys.push(sk);
        SEKeypair {
            id: self.keys.len() - 1,
            key_pub,
        }
    }

    /// Signs a message with the private key referenced by id.
    /// No checks are done to make sure this id exists or is tied to the current
    /// application.
    pub fn sign(&self, id: usize, msg: &VerifierMessage) -> ecdsa::Signature {
        ecdsa::Signature::new_prehashed(&mut StdRng::seed_from_u64(0u64), msg.into(), self.keys[id])
    }
}

/// A [SecureElement] keypair, with the private key stored in the
/// [SecureElement] only, and only accessible via its id.
pub struct SEKeypair {
    pub id: usize,
    pub key_pub: SecP256Affine,
}

impl Swiyu {
    /// Create a new [Swiyu] app. Of course the real app will do so much
    /// more to initialize itself. But here it's mostly a placeholder to
    /// show which actor does which parts.
    pub fn new(setup: PublicSetup) -> Self {
        Self {
            setup,
            key_id: None,
            vcs: None,
        }
    }

    /// Add a [VerifiedCredential].
    /// In this simple implementation, only one [VerifiedCredential] can exist.
    pub fn add_vc(&mut self, key_id: usize, credential: VerifiedCredential) {
        if self.vcs.is_some() {
            panic!("Can only have one credential");
        }
        self.key_id = Some(key_id);
        self.vcs = Some(credential);
    }

    /// Returns a [BBSPresentation] which is a proof that the holder knows the
    /// messages signed by the [Issuer].
    /// In addition to the normal protocol, this adds two [PublicCommitment]s
    /// to the proof, which hide the public key of the holder.
    /// When creating a [BBSPresentation], the [PublicCommitment]s are Open, meaning
    /// that their random values are accessible.
    /// Before sending a [BBSPresentation] to an untrusted entity, one must call
    /// [BBSPresentation::close()] to remove the random values.
    pub fn blinded_presentation(
        &mut self,
        message: &VerifierMessage,
        reveal: &[usize],
    ) -> BBSPresentation {
        let vc = self.vcs.as_ref().expect("No credential yet!");
        let mut messages_and_blindings = vec![
            // TODO: this is the last part of the ECDSA proof which is not implemented
            // yet, or where I couldn't find the implementation, neither in Ubique's
            // code, nor in docknetwork's code.
            // Without the proof that the blinded public key used to verify the ECDSA signature
            // is actually in the BBS proof, an important part of the protocol is missing.
            // However, it does not seem unsurmountable to extend the BBS proofs to allow
            // for including commitments.
            // This would then be part of the Interfaces described in the
            // [IRTF-BBS-Signatures Draft](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/).
            MessageOrBlinding::BlindMessageWithConcreteBlinding {
                message: &vc.messages[0],
                blinding: BlsFr::zero(),
            },
            MessageOrBlinding::BlindMessageWithConcreteBlinding {
                message: &vc.messages[1],
                blinding: BlsFr::zero(),
            },
        ];

        // Add the first- or last-name, depending on the request.
        let mut message_strings = HashMap::new();
        let mut revealed = BTreeMap::new();
        for idx in [
            VerifiedCredential::FIELD_FIRSTNAME,
            VerifiedCredential::FIELD_LASTNAME,
        ] {
            let msg = &vc.messages[idx];
            if reveal.contains(&idx) {
                messages_and_blindings.push(MessageOrBlinding::RevealMessage(msg));
                message_strings.insert(idx, vc.message_strings[&idx].clone());
                revealed.insert(idx, msg.clone());
            } else {
                messages_and_blindings.push(MessageOrBlinding::BlindMessageRandomly(msg));
            }
        }

        let proof = PoKOfSignatureG1Protocol::init(
            &mut self.setup.rng,
            &vc.signature,
            &self.setup.sig_params_g1,
            messages_and_blindings,
        )
        .unwrap()
        .gen_proof(&message.into())
        .unwrap();

        BBSPresentation {
            proof,
            revealed,
            message_strings,
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
    /// Create a new commitment from a scalar. This returns an Open commitment,
    /// including the random value.
    pub fn from_message(setup: &mut PublicSetup, message: &BlsFr) -> Self {
        let blinding_factor = BlsFr::rand(&mut setup.rng);
        Self::Open(
            blinding_factor,
            setup.comm_key_bls.commit(message, &blinding_factor),
        )
    }

    /// Close this commitment by discarding the random value.
    /// For security, this consumes the [PublicCommitment].
    pub fn close(self) -> Self {
        match self {
            PublicCommitment::Open(_, affine) => PublicCommitment::Closed(affine),
            _ => self,
        }
    }

    /// Returns the random value of this commitment.
    /// If the commitment is closed, it panics.
    pub fn rand(&self) -> BlsFr {
        match self {
            PublicCommitment::Open(fp, _) => fp.clone(),
            _ => panic!("No random value in closed commitment"),
        }
    }

    /// Returns the affine, public, value of this commitment, which is always available.
    pub fn affine(&self) -> BlsG1Affine {
        match self {
            PublicCommitment::Open(_, affine) => affine.clone(),
            PublicCommitment::Closed(affine) => affine.clone(),
        }
    }

    /// Make sure the commitment has been closed.
    pub fn assert_closed(&self) {
        if let Self::Open(_, _) = self {
            panic!("PublicCommitment is open and leaks random value!");
        }
    }
}

/// Globally known public values.
/// These values can be created by anyone and are needed by all actors.
#[derive(Clone)]
pub struct PublicSetup {
    /// Random Number Generator
    rng: StdRng,
    /// Parameters for the BBS signatures
    sig_params_g1: SignatureParamsG1<Bls12_381>,
    /// Bulletproof setup parameters - usually created by the verifier and then sent to the prover.
    bpp_setup_params: BppSetupParams<Affine<Tom256Config>>,
    /// Commitment generators for the Tom-256 keys
    comm_key_tom: PedersenCommitmentKey<Tom256Affine>,
    /// Commitment generators for the SecP256 keys
    comm_key_secp: PedersenCommitmentKey<SecP256Affine>,
    /// Commitment generators for the Bls12-381 keys
    comm_key_bls: PedersenCommitmentKey<BlsG1Affine>,
}

impl PublicSetup {
    // These constants define also the security level of the proofs created in [BBSPresentation].
    const WITNESS_BIT_SIZE: usize = 64;
    const CHALLENGE_BIT_SIZE: usize = 180;
    const ABORT_PARAM: usize = 8;
    const RESPONSE_BYTE_SIZE: usize = 32;
    const NUM_REPS: usize = 1;
    const NUM_CHUNKS: usize = 4;
    const BPP_BASE: u16 = 2;

    /// Create a new [PublicSetup]. It can also be [Clone]d, or created new.
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

    /// For the proofs it is important to enter all variables in the transcript, and then hash
    /// them to create a challenge.
    /// If the prover can modify values which are not part of the transcript, they might get
    /// an advantage and manage to create a wrong proof.
    fn append_transcript<T: Transcript + Clone + Write>(&self, pt: &mut T) {
        pt.append(b"comm_key_secp", &self.comm_key_secp);
        pt.append(b"comm_key_tom", &self.comm_key_tom);
        pt.append(b"comm_key_bls", &self.comm_key_bls);
        pt.append(b"bpp_setup_params", &self.bpp_setup_params);
    }
}

/// Parametrization of the discreet log equality proof.
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

    /// Create a new proof that the public key stored in a commitment can be used
    /// to verify a signature.
    /// This follows the excellent work done by Lovesh in
    /// [docknetwork/crypto](https://github.com/docknetwork/crypto/blob/main/equality_across_groups/src/pok_ecdsa_pubkey.rs#L462).
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

        // Create the transcript which will be used for the challenge.
        // All variables which can be chosen by the prover must find their way into the transcript,
        // else the prover can have an advantage in creating a wrong proof.
        let mut prover_transcript = new_merlin_transcript(b"test");
        setup.append_transcript(&mut prover_transcript);
        Self::append_transcript(
            &mut prover_transcript,
            &comm_pk.comm,
            &bbs_presentation,
            &verifier_message.into(),
        );

        // Create a protocol to prove that the `transformed_sig` on the `verifier_message`
        // can be verified using the commitment `comm_pk`.
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

        // Proof that the x coordinate is same in both Tom-256 and BLS12-381 commitments
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

        // Proof that the y coordinate is same in both Tom-256 and BLS12-381 commitments
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

    /// Verifies that the commitments to the signature and the public key of the holder
    /// verify the `message` from the verifier. The [BBSPresentation] is used for the commitments
    /// to the holder's public key.
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

        // Exercise for the reader: verify_using_randomized_mult_checker can be used to make it much faster.
        // See [docknetwork/crypto](https://github.com/docknetwork/crypto/blob/main/equality_across_groups/src/pok_ecdsa_pubkey.rs#L434)
        self.proof
            .verify(
                message,
                &self.comm_pk,
                &challenge_verifier,
                &setup.comm_key_secp,
                &setup.comm_key_tom,
            )
            .expect("ECDSA proof failed");

        // Verify the proof for the equality between the Tom-256 commitment and the BBS-commitment:
        // x-coordinate
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

        // Verify the proof for the equality between the Tom-256 commitment and the BBS-commitment:
        // y-coordinate
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

    // Put the relevant entries in the transcript.
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
    /// Make sure the BBSPresentation is closed - a better version would use the
    /// `*Protocol` and `*Proof` like in the rest of docknetwork/crypto library.
    pub fn assert_closed(&self) {
        self.commitment_pub_x.assert_closed();
        self.commitment_pub_y.assert_closed();
    }

    /// Close the commitments by removing the random values.
    pub fn close(self) -> Self {
        Self {
            proof: self.proof,
            revealed: self.revealed,
            message_strings: self.message_strings,
            commitment_pub_x: self.commitment_pub_x.close(),
            commitment_pub_y: self.commitment_pub_y.close(),
        }
    }

    /// Verify that:
    /// - the signature can be verified by the certificate
    /// - the signature matches the messages
    /// - the message_strings match the messages
    /// - TODO: the signature matches the commitment_pub
    pub fn verify(
        &self,
        setup: PublicSetup,
        issuer_certificate: PublicKeyG2<Bls12_381>,
        verifier_message: &BlsFr,
    ) -> Result<(), BBSPlusError> {
        // Is the BBS proof valid?
        self.proof.verify(
            &self.revealed,
            verifier_message,
            issuer_certificate,
            setup.sig_params_g1.clone(),
        )?;

        // Check all the revealed message strings to match the BBS messages.
        for (rev_id, bbs_msg) in &self.revealed {
            match self.message_strings.get(rev_id) {
                Some(msg_str) => {
                    if bbs_msg != &(&VerifierMessage(msg_str.clone())).into() {
                        return Err(BBSPlusError::InvalidSignature);
                    }
                }
                None => return Err(BBSPlusError::IncorrectNoOfShares(*rev_id, 0)),
            }
        }

        // TODO: check that the commitment_pub_x and commitment_pub_y are in the BBS proof.

        Ok(())
    }

    /// Returns the optional message_string at position `idx`.
    /// If `Verify` has not been called, this is not reliable!
    pub fn message_string(&self, idx: usize) -> Option<String> {
        self.message_strings.get(&idx).cloned()
    }
}
#[cfg(test)]
mod test {
    use std::{collections::BTreeMap, error::Error};

    use ark_ff::BigInt;

    use super::*;

    // A complete tewst of the ECDSA signature verification.
    #[test]
    fn sign_verify_msg() -> Result<(), Box<dyn Error>> {
        // Set up parties
        let setup = PublicSetup::new();
        let mut issuer = Issuer::new(setup.clone());
        let mut holder = MobilePhone::new(setup.clone());
        let mut verifier = Verifier::new(setup.clone(), issuer.get_certificate());

        // Install the swiyu app and add a credential
        holder.install_swiyu();
        let se_kp = holder.secure_element().create_kp();
        let credential = issuer.new_credential(se_kp.key_pub);
        holder.swiyu().add_vc(se_kp.id, credential);

        // Verifier requests a presentation from the holder
        let message = &verifier.create_message();

        // Holder creates a blinded presentation, an ECDSA signature, and a proof.
        // This is of course all done in the Swiyu app, but here we do it step-by-step.
        let presentation = holder
            .swiyu()
            .blinded_presentation(&message, &[VerifiedCredential::FIELD_FIRSTNAME]);
        let signature = holder.secure_element().sign(0, &message);
        let proof = ECDSAProof::new(
            setup,
            se_kp.key_pub,
            presentation.clone(),
            signature,
            &message,
        );
        let presentation_closed = presentation.close();

        // Holder sends the proof to the verifier, which checks it.
        verifier.check_proof(message, presentation_closed.clone(), proof.clone());
        assert_eq!(
            presentation_closed.message_string(VerifiedCredential::FIELD_FIRSTNAME),
            Some(format!("123"))
        );
        assert_eq!(
            presentation_closed.message_string(VerifiedCredential::FIELD_LASTNAME),
            None
        );
        Ok(())
    }

    /// This is for testing whether we can simply include a blinded message in a BBS
    /// proof - with the answer: NO!
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

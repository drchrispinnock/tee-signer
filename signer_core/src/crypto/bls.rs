use crate::{
    crypto::{
        self, CryptoRngCore, Deserialize, KeyPair, PossessionProver, ProofVerifier, Random,
        Serialize, SigningVersion, Verifier,
    },
    serde_helper,
};
use blst::min_pk;
pub use blst::BLST_ERROR;
use format_bytes::{format_bytes, DisplayBytes};
use std::fmt::Display;

#[derive(Debug, Clone)]
pub enum Scheme {
    Basic,
    MessageAugmentation,
    ProofOfPossession,
}

impl Display for Scheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Scheme::Basic => "NUL",
            Scheme::MessageAugmentation => "AUG",
            Scheme::ProofOfPossession => "POP",
        })
    }
}

impl DisplayBytes for Scheme {
    fn display_bytes(&self, output: &mut dyn std::io::Write) -> std::io::Result<()> {
        output
            .write(match self {
                Scheme::Basic => b"NUL",
                Scheme::MessageAugmentation => b"AUG",
                Scheme::ProofOfPossession => b"POP",
            })
            .and(Ok(()))
    }
}

#[derive(Debug, Clone)]
pub enum CipherSuite {
    Signature(u8, Scheme),
    ProofOfPossession(u8, Scheme),
}

impl From<CipherSuite> for Vec<u8> {
    fn from(val: CipherSuite) -> Self {
        match val {
            CipherSuite::Signature(g, scheme) => {
                format_bytes!(b"BLS_SIG_BLS12381G{}_XMD:SHA-256_SSWU_RO_{}_", g, scheme)
            }
            CipherSuite::ProofOfPossession(g, scheme) => {
                format_bytes!(b"BLS_POP_BLS12381G{}_XMD:SHA-256_SSWU_RO_{}_", g, scheme)
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct Signature(min_pk::Signature);

impl core::ops::Deref for Signature {
    type Target = min_pk::Signature;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// use compressed form for serialization
impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0.compress())
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = deserializer.deserialize_bytes(serde_helper::ByteArrayVisitor::<96>::new())?;
        match min_pk::Signature::uncompress(&bytes) {
            Ok(val) => Ok(Signature(val)),
            Err(err) => Err(serde::de::Error::custom(Error::from(err))),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProofOfPossession(min_pk::Signature);

impl core::ops::Deref for ProofOfPossession {
    type Target = min_pk::Signature;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// use compressed form for serialization
impl Serialize for ProofOfPossession {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0.compress())
    }
}

impl<'de> Deserialize<'de> for ProofOfPossession {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = deserializer.deserialize_bytes(serde_helper::ByteArrayVisitor::<96>::new())?;
        match min_pk::Signature::uncompress(&bytes) {
            Ok(val) => Ok(ProofOfPossession(val)),
            Err(err) => Err(serde::de::Error::custom(Error::from(err))),
        }
    }
}

#[derive(Debug)]
pub struct PublicKey(min_pk::PublicKey);

impl core::ops::Deref for PublicKey {
    type Target = min_pk::PublicKey;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Verifier<Signature> for PublicKey {
    fn verify(
        &self,
        msg: &[u8],
        signature: &Signature,
        version: SigningVersion,
    ) -> Result<(), crypto::Error> {
        let blst_error = match version {
            SigningVersion::V0 => Err(crypto::Error::InvalidSigningVersion),
            SigningVersion::V1 => {
                let aug = self.to_bytes();
                let cipher_suite: Vec<u8> =
                    CipherSuite::Signature(2, Scheme::MessageAugmentation).into();
                Ok(signature
                    .0
                    .verify(true, msg, &cipher_suite, &aug, self, true))
            }
            SigningVersion::V2 | SigningVersion::Latest => {
                let cipher_suite: Vec<u8> =
                    CipherSuite::Signature(2, Scheme::ProofOfPossession).into();
                Ok(signature
                    .0
                    .verify(true, msg, &cipher_suite, &[], self, true))
            }
        }?;
        match blst_error {
            blst::BLST_ERROR::BLST_SUCCESS => Ok(()),
            err => {
                let b: Box<dyn std::error::Error + Send + Sync> = Box::new(Error::from(err));
                Err(crypto::Error::Signature(b.into()))
            }
        }
    }
}

impl ProofVerifier<ProofOfPossession> for PublicKey {
    fn verify_pop(&self, proof: &ProofOfPossession) -> Result<(), crypto::Error> {
        let cipher_suite: Vec<u8> =
            CipherSuite::ProofOfPossession(2, Scheme::ProofOfPossession).into();
        match proof
            .0
            .verify(true, &self.to_bytes(), &cipher_suite, &[], self, true)
        {
            blst::BLST_ERROR::BLST_SUCCESS => Ok(()),
            err => {
                let b: Box<dyn std::error::Error + Send + Sync> = Box::new(Error::from(err));
                Err(crypto::Error::Signature(b.into()))
            }
        }
    }
}

// use compressed form for serialization
impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0.compress())
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = deserializer.deserialize_bytes(serde_helper::ByteArrayVisitor::<48>::new())?;
        match min_pk::PublicKey::uncompress(&bytes) {
            Ok(val) => Ok(PublicKey(val)),
            Err(err) => Err(serde::de::Error::custom(Error::from(err))),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SigningKey(pub(crate) min_pk::SecretKey);

impl core::ops::Deref for SigningKey {
    type Target = min_pk::SecretKey;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Random for SigningKey {
    type Error = Error;
    fn random<R: CryptoRngCore>(r: &mut R) -> Result<Self, Error> {
        let mut ikm: [u8; 32] = [0; 32];
        r.fill_bytes(&mut ikm);
        Ok(SigningKey(min_pk::SecretKey::key_gen(&ikm, &[])?))
    }
}

impl KeyPair for SigningKey {
    type PublicKey = PublicKey;
    type Error = crypto::Error;
    type Signature = Signature;

    fn public_key(&self) -> Self::PublicKey {
        PublicKey(self.sk_to_pk())
    }

    fn try_sign(
        &self,
        msg: &[u8],
        version: SigningVersion,
    ) -> Result<Self::Signature, Self::Error> {
        match version {
            SigningVersion::V0 => Err(crypto::Error::InvalidSigningVersion),
            SigningVersion::V1 => {
                let aug = self.sk_to_pk().to_bytes();
                let cipher_suite: Vec<u8> =
                    CipherSuite::Signature(2, Scheme::MessageAugmentation).into();
                Ok(Signature(self.sign(msg, &cipher_suite, &aug)))
            }
            SigningVersion::V2 | SigningVersion::Latest => {
                let cipher_suite: Vec<u8> =
                    CipherSuite::Signature(2, Scheme::ProofOfPossession).into();
                Ok(Signature(self.sign(msg, &cipher_suite, &[])))
            }
        }
    }

    fn try_sign_digest(&self, digest: &[u8]) -> Result<Self::Signature, Self::Error> {
        let cipher_suite: Vec<u8> = CipherSuite::Signature(2, Scheme::ProofOfPossession).into();
        Ok(Signature(self.sign(digest, &cipher_suite, &[])))
    }
}

impl PossessionProver for SigningKey {
    type Proof = ProofOfPossession;
    type Error = crypto::Error;

    fn try_prove(&self) -> Result<Self::Proof, Self::Error> {
        let pk = self.sk_to_pk().to_bytes();
        let cipher_suite: Vec<u8> =
            CipherSuite::ProofOfPossession(2, Scheme::ProofOfPossession).into();
        Ok(ProofOfPossession(self.sign(&pk, &cipher_suite, &[])))
    }
}

impl Serialize for SigningKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0.serialize())
    }
}

impl<'de> Deserialize<'de> for SigningKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = deserializer.deserialize_bytes(serde_helper::ByteArrayVisitor::<32>::new())?;
        match min_pk::SecretKey::deserialize(&bytes) {
            Ok(val) => Ok(SigningKey(val)),
            Err(err) => Err(serde::de::Error::custom(Error::from(err))),
        }
    }
}

#[derive(Debug)]
pub struct Error(pub BLST_ERROR);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            BLST_ERROR::BLST_SUCCESS => f.write_str("Success"),
            BLST_ERROR::BLST_BAD_ENCODING => f.write_str("Bad encoding"),
            BLST_ERROR::BLST_POINT_NOT_ON_CURVE => f.write_str("Point not on curve"),
            BLST_ERROR::BLST_POINT_NOT_IN_GROUP => f.write_str("Point not in group"),
            BLST_ERROR::BLST_AGGR_TYPE_MISMATCH => f.write_str("Aggregate type mismatch"),
            BLST_ERROR::BLST_VERIFY_FAIL => f.write_str("Verify fail"),
            BLST_ERROR::BLST_PK_IS_INFINITY => f.write_str("PK is infinity"),
            BLST_ERROR::BLST_BAD_SCALAR => f.write_str("Bad scalar"),
        }
    }
}

impl From<BLST_ERROR> for Error {
    fn from(value: BLST_ERROR) -> Self {
        Error(value)
    }
}

impl std::error::Error for Error {}

/// Real Tezos mainnet consensus signatures from tz4 bakers (see testdata/). These pin down that
/// `SigningVersion::V2` matches what the protocol verifies, and confirm the BLS-mode payload layout
/// the consensus-mode parser relies on.
#[cfg(test)]
mod mainnet_vectors {
    use super::{min_pk, PublicKey, Signature};
    use crate::crypto::{SigningVersion, Verifier};

    const VECTORS: &str = include_str!("../../testdata/tz4_consensus_vectors.json");

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn vectors() -> Vec<serde_json::Value> {
        let v: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
        v["vectors"].as_array().unwrap().clone()
    }

    #[test]
    fn layout_matches_level_and_round() {
        for v in vectors() {
            let msg = hex(v["message_hex"].as_str().unwrap());
            assert_eq!(msg.len(), 78);
            let (magic, tag) = match v["kind"].as_str().unwrap() {
                "preattestation" => (0x12, 40),
                _ => (0x13, 41),
            };
            assert_eq!(msg[0], magic);
            assert_eq!(msg[37], tag);
            let level = i32::from_be_bytes(msg[38..42].try_into().unwrap());
            let round = i32::from_be_bytes(msg[42..46].try_into().unwrap());
            assert_eq!(level as i64, v["level"].as_i64().unwrap());
            assert_eq!(round as i64, v["round"].as_i64().unwrap());
        }
    }

    #[test]
    fn single_key_signatures_verify_with_v2() {
        let mut n = 0;
        for v in vectors()
            .iter()
            .filter(|v| v["single_key"].as_bool().unwrap())
        {
            let msg = hex(v["message_hex"].as_str().unwrap());
            let pk = PublicKey(
                min_pk::PublicKey::uncompress(&hex(v["consensus_pk_hex"].as_str().unwrap()))
                    .unwrap(),
            );
            let sig = Signature(
                min_pk::Signature::uncompress(&hex(v["signature_hex"].as_str().unwrap())).unwrap(),
            );
            pk.verify(&msg, &sig, SigningVersion::V2)
                .unwrap_or_else(|e| panic!("{} level {}: {e:?}", v["kind"], v["level"]));
            // Flipping one byte of the payload must break it.
            let mut bad = msg.clone();
            bad[45] ^= 1;
            assert!(pk.verify(&bad, &sig, SigningVersion::V2).is_err());
            n += 1;
        }
        assert!(n >= 4, "expected at least 4 single-key vectors, got {n}");
    }
}

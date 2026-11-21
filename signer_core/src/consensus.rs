//! Enclave-side consensus policy: a strict parser for the Tezos consensus payloads a tz4 baker
//! signs, and the high-watermark rule. See `doc/consensus-mode.md`.
//!
//! Everything here is pure (no I/O) so it can be reviewed and tested in isolation. The signer
//! refuses to sign unless [`parse`] accepts the payload and [`Watermarks::check`] allows it.

use crate::crypto::Blake2b256;
use blake2::Digest;

pub const CHAIN_ID_LEN: usize = 4;

const MAGIC_BLOCK: u8 = 0x11;
const MAGIC_PREATTESTATION: u8 = 0x12;
const MAGIC_ATTESTATION: u8 = 0x13;

/// Octez `Operation_repr.Encoding.Bls_mode` tags: (pre)attestations signed by BLS keys omit the
/// slot so that every delegate signs the same bytes (needed for PoP aggregation).
const TAG_BLS_MODE_PREATTESTATION: u8 = 40;
const TAG_BLS_MODE_ATTESTATION: u8 = 41;

/// magic(1) chain_id(4) branch(32) tag(1) level(4) round(4) block_payload_hash(32)
const BLS_MODE_CONSENSUS_LEN: usize = 78;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Kind {
    Block,
    Preattestation,
    Attestation,
}

/// What a consensus-mode key may sign. Fixed at key generation and sealed with the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Consensus key: blocks, preattestations, attestations.
    Consensus,
    /// DAL companion key: attestations only (it signs the same bytes as the consensus key).
    Companion,
}

impl Role {
    pub fn allows(self, kind: Kind) -> bool {
        match self {
            Role::Consensus => true,
            Role::Companion => kind == Kind::Attestation,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub kind: Kind,
    pub chain_id: [u8; CHAIN_ID_LEN],
    pub level: i32,
    pub round: i32,
    /// Blake2b-256 of the whole payload, so an identical request can be re-signed.
    pub digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Empty,
    UnknownMagic(u8),
    BadLength { kind: Kind, len: usize },
    BadTag { kind: Kind, tag: u8 },
    BadFitness(&'static str),
    WrongChain,
    NotAllowedForRole(Kind),
    BelowWatermark { kind: Kind, level: i32, round: i32 },
    NegativeLevelOrRound,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Empty => f.write_str("empty payload"),
            Error::UnknownMagic(m) => write!(f, "not a consensus payload (magic byte {m:#04x})"),
            Error::BadLength { kind, len } => {
                write!(f, "{kind:?} payload has invalid length {len}")
            }
            Error::BadTag { kind, tag } => write!(f, "{kind:?} payload has unexpected tag {tag}"),
            Error::BadFitness(why) => write!(f, "invalid block fitness: {why}"),
            Error::WrongChain => f.write_str("chain id does not match the key's policy"),
            Error::NotAllowedForRole(kind) => write!(f, "this key may not sign {kind:?} payloads"),
            Error::BelowWatermark { kind, level, round } => write!(
                f,
                "{kind:?} at level {level} round {round} is not above the high watermark"
            ),
            Error::NegativeLevelOrRound => f.write_str("negative level or round"),
        }
    }
}

impl std::error::Error for Error {}

fn be_i32(b: &[u8], at: usize) -> i32 {
    i32::from_be_bytes(b[at..at + 4].try_into().unwrap())
}

fn be_u32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(b[at..at + 4].try_into().unwrap())
}

/// Parse a payload as received from the baker (watermark byte included). Anything that is not
/// exactly one of the accepted consensus forms is an error.
pub fn parse(msg: &[u8]) -> Result<Request, Error> {
    let magic = *msg.first().ok_or(Error::Empty)?;
    let (kind, level, round) = match magic {
        MAGIC_PREATTESTATION | MAGIC_ATTESTATION => {
            let (kind, want_tag) = if magic == MAGIC_PREATTESTATION {
                (Kind::Preattestation, TAG_BLS_MODE_PREATTESTATION)
            } else {
                (Kind::Attestation, TAG_BLS_MODE_ATTESTATION)
            };
            if msg.len() != BLS_MODE_CONSENSUS_LEN {
                return Err(Error::BadLength {
                    kind,
                    len: msg.len(),
                });
            }
            let tag = msg[37];
            if tag != want_tag {
                return Err(Error::BadTag { kind, tag });
            }
            (kind, be_i32(msg, 38), be_i32(msg, 42))
        }
        MAGIC_BLOCK => {
            let (level, round) = parse_block(msg)?;
            (Kind::Block, level, round)
        }
        other => return Err(Error::UnknownMagic(other)),
    };
    if level < 0 || round < 0 {
        return Err(Error::NegativeLevelOrRound);
    }
    let mut chain_id = [0u8; CHAIN_ID_LEN];
    chain_id.copy_from_slice(&msg[1..1 + CHAIN_ID_LEN]);
    Ok(Request {
        kind,
        chain_id,
        level,
        round,
        digest: Blake2b256::digest(msg).into(),
    })
}

/// magic(1) chain_id(4) | shell header: level(i32) proto(u8) predecessor(32) timestamp(i64)
/// validation_pass(u8) operations_hash(32) fitness(u32 length + elements) context(32) | protocol data
fn parse_block(msg: &[u8]) -> Result<(i32, i32), Error> {
    const FITNESS_AT: usize = 1 + 4 + 4 + 1 + 32 + 8 + 1 + 32; // 83
    let bad_len = Error::BadLength {
        kind: Kind::Block,
        len: msg.len(),
    };
    if msg.len() < FITNESS_AT + 4 {
        return Err(bad_len);
    }
    let level = be_i32(msg, 5);
    let fitness_len = be_u32(msg, FITNESS_AT) as usize;
    let fit_start = FITNESS_AT + 4;
    let fit_end = fit_start.checked_add(fitness_len).ok_or(bad_len.clone())?;
    // context(32) plus at least payload_hash(32) and payload_round(4) of protocol data must follow.
    if msg.len() < fit_end + 32 + 36 {
        return Err(bad_len);
    }
    let fitness = &msg[fit_start..fit_end];

    // Tenderbake fitness: [version=0x02] [level] [locked_round: 0 or 4 bytes]
    // [predecessor_round] [round], each element prefixed by its u32 length.
    let mut elems: Vec<&[u8]> = Vec::with_capacity(5);
    let mut i = 0;
    while i < fitness.len() {
        if i + 4 > fitness.len() {
            return Err(Error::BadFitness("truncated element length"));
        }
        let n = be_u32(fitness, i) as usize;
        i += 4;
        if i + n > fitness.len() {
            return Err(Error::BadFitness("truncated element"));
        }
        elems.push(&fitness[i..i + n]);
        i += n;
    }
    match elems.as_slice() {
        [version, f_level, locked, pred_round, round]
            if *version == [0x02]
                && f_level.len() == 4
                && (locked.is_empty() || locked.len() == 4)
                && pred_round.len() == 4
                && round.len() == 4 =>
        {
            if be_i32(f_level, 0) != level {
                return Err(Error::BadFitness("fitness level differs from header level"));
            }
            Ok((level, be_i32(round, 0)))
        }
        _ => Err(Error::BadFitness("not a Tenderbake fitness")),
    }
}

/// Last signed position for one kind of operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mark {
    pub level: i32,
    pub round: i32,
    pub digest: [u8; 32],
}

/// High watermarks for one key: one [`Mark`] per [`Kind`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Watermarks {
    pub block: Option<Mark>,
    pub preattestation: Option<Mark>,
    pub attestation: Option<Mark>,
}

impl Watermarks {
    pub fn get(&self, kind: Kind) -> Option<&Mark> {
        match kind {
            Kind::Block => self.block.as_ref(),
            Kind::Preattestation => self.preattestation.as_ref(),
            Kind::Attestation => self.attestation.as_ref(),
        }
    }

    fn slot(&mut self, kind: Kind) -> &mut Option<Mark> {
        match kind {
            Kind::Block => &mut self.block,
            Kind::Preattestation => &mut self.preattestation,
            Kind::Attestation => &mut self.attestation,
        }
    }

    /// Same rule as Signatory's `Watermark.Validate`: sign if `(level, round)` is strictly above
    /// the stored mark, or if the payload is byte-identical to the last one signed.
    pub fn check(&self, req: &Request) -> Result<(), Error> {
        match self.get(req.kind) {
            None => Ok(()),
            Some(m) if m.digest == req.digest => Ok(()),
            Some(m) if (req.level, req.round) > (m.level, m.round) => Ok(()),
            Some(_) => Err(Error::BelowWatermark {
                kind: req.kind,
                level: req.level,
                round: req.round,
            }),
        }
    }

    /// Record a signed request. Call only after [`Watermarks::check`] succeeded.
    pub fn advance(&mut self, req: &Request) {
        *self.slot(req.kind) = Some(Mark {
            level: req.level,
            round: req.round,
            digest: req.digest,
        });
    }
}

/// Full policy check for one request: parse, chain, role, watermark.
pub fn authorize(
    msg: &[u8],
    chain_id: &[u8; CHAIN_ID_LEN],
    role: Role,
    marks: &Watermarks,
) -> Result<Request, Error> {
    let req = parse(msg)?;
    if &req.chain_id != chain_id {
        return Err(Error::WrongChain);
    }
    if !role.allows(req.kind) {
        return Err(Error::NotAllowedForRole(req.kind));
    }
    marks.check(&req)?;
    Ok(req)
}

#[cfg(test)]
mod tests {
    use super::*;

    const VECTORS: &str = include_str!("../testdata/tz4_consensus_vectors.json");
    const MAINNET: [u8; 4] = [0x7a, 0x06, 0xa7, 0x70]; // NetXdQprcVkpaWU

    // Signatory's block test vector (pkg/signatory/request/request_test.go): level 20878, round 0,
    // chain id ed9d217c (an older test network). Tenderbake header layout is unchanged since.
    const BLOCK: &str = "11ed9d217c0000518e0118425847ac255b6d7c30ce8fec23b8eaf13b741de7d18509ac2ef83c741209630000000061947af504805682ea5d089837764b3efcc90b91db24294ff9ddb66019f332ccba17cc4741000000210000000102000000040000518e0000000000000004ffffffff0000000400000000eb1320a71e8bf8b0162a3ec315461e9153a38b70d00d5dde2df85eb92748f8d068d776e356683a9e23c186ccfb72ddc6c9857bb1704487972922e7c89a7121f800000000a8e1dd3c000000000000";

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn mainnet_messages() -> Vec<(Vec<u8>, serde_json::Value)> {
        let v: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
        v["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| (hex(v["message_hex"].as_str().unwrap()), v.clone()))
            .collect()
    }

    #[test]
    fn parses_mainnet_tz4_payloads() {
        for (msg, v) in mainnet_messages() {
            let r = parse(&msg).unwrap();
            assert_eq!(r.chain_id, MAINNET);
            assert_eq!(r.level as i64, v["level"].as_i64().unwrap());
            assert_eq!(r.round as i64, v["round"].as_i64().unwrap());
            let want = if v["kind"] == "preattestation" {
                Kind::Preattestation
            } else {
                Kind::Attestation
            };
            assert_eq!(r.kind, want);
        }
    }

    #[test]
    fn parses_block() {
        let r = parse(&hex(BLOCK)).unwrap();
        assert_eq!(r.kind, Kind::Block);
        assert_eq!((r.level, r.round), (20878, 0));
        assert_eq!(r.chain_id, [0xed, 0x9d, 0x21, 0x7c]);
    }

    #[test]
    fn block_round_comes_from_fitness() {
        let mut b = hex(BLOCK);
        // fitness starts at 87; round is its last 4 bytes (87 + 33 - 4 = 116)
        b[116..120].copy_from_slice(&3i32.to_be_bytes());
        assert_eq!(parse(&b).unwrap().round, 3);
    }

    #[test]
    fn rejects_non_consensus_and_malformed() {
        let (att, _) = mainnet_messages()
            .into_iter()
            .find(|(m, _)| m[0] == 0x13)
            .unwrap();
        // generic operation (transfer etc.)
        let mut generic = att.clone();
        generic[0] = 0x03;
        assert_eq!(parse(&generic), Err(Error::UnknownMagic(0x03)));
        // tz1-style attestation with slot (tag 21, 80 bytes)
        let mut tz1 = att[..37].to_vec();
        tz1.extend_from_slice(&[21, 0, 7]);
        tz1.extend_from_slice(&att[38..]);
        assert!(matches!(parse(&tz1), Err(Error::BadLength { .. })));
        // right length, wrong tag
        let mut tag = att.clone();
        tag[37] = 40;
        assert!(matches!(parse(&tag), Err(Error::BadTag { .. })));
        // trailing byte
        let mut long = att.clone();
        long.push(0);
        assert!(matches!(parse(&long), Err(Error::BadLength { .. })));
        assert_eq!(parse(&[]), Err(Error::Empty));
        // block whose fitness level disagrees with the header
        let mut b = hex(BLOCK);
        b[99] ^= 1;
        assert!(matches!(parse(&b), Err(Error::BadFitness(_))));
        // truncated block
        assert!(parse(&hex(BLOCK)[..100]).is_err());
    }

    #[test]
    fn watermark_rules() {
        let (att, _) = mainnet_messages()
            .into_iter()
            .find(|(m, _)| m[0] == 0x13)
            .unwrap();
        let at = |level: i32, round: i32| {
            let mut m = att.clone();
            m[38..42].copy_from_slice(&level.to_be_bytes());
            m[42..46].copy_from_slice(&round.to_be_bytes());
            m
        };
        let mut w = Watermarks::default();
        let r = authorize(&at(100, 0), &MAINNET, Role::Consensus, &w).unwrap();
        w.advance(&r);
        // identical bytes: allowed (re-sign after a lost response)
        assert!(authorize(&at(100, 0), &MAINNET, Role::Consensus, &w).is_ok());
        // same level and round, different payload: double sign, refused
        let mut other = at(100, 0);
        other[50] ^= 1;
        assert!(matches!(
            authorize(&other, &MAINNET, Role::Consensus, &w),
            Err(Error::BelowWatermark { .. })
        ));
        // lower level: refused; higher round or level: allowed
        assert!(authorize(&at(99, 5), &MAINNET, Role::Consensus, &w).is_err());
        assert!(authorize(&at(100, 1), &MAINNET, Role::Consensus, &w).is_ok());
        assert!(authorize(&at(101, 0), &MAINNET, Role::Consensus, &w).is_ok());
        // kinds are independent: a preattestation at level 100 is still fine
        let mut pre = at(100, 0);
        pre[0] = 0x12;
        pre[37] = 40;
        assert!(authorize(&pre, &MAINNET, Role::Consensus, &w).is_ok());
    }

    #[test]
    fn chain_and_role_policy() {
        let (att, _) = mainnet_messages()
            .into_iter()
            .find(|(m, _)| m[0] == 0x13)
            .unwrap();
        let (pre, _) = mainnet_messages()
            .into_iter()
            .find(|(m, _)| m[0] == 0x12)
            .unwrap();
        let w = Watermarks::default();
        assert_eq!(
            authorize(&att, &[0, 0, 0, 0], Role::Consensus, &w),
            Err(Error::WrongChain)
        );
        assert!(authorize(&att, &MAINNET, Role::Companion, &w).is_ok());
        assert_eq!(
            authorize(&pre, &MAINNET, Role::Companion, &w),
            Err(Error::NotAllowedForRole(Kind::Preattestation))
        );
        assert_eq!(
            authorize(&hex(BLOCK), &[0xed, 0x9d, 0x21, 0x7c], Role::Companion, &w),
            Err(Error::NotAllowedForRole(Kind::Block))
        );
    }
}

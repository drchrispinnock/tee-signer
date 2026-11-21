# Consensus mode: enclave-enforced policy and high watermark

Status: design draft (fork `drchrispinnock/tee-signer`, branch `consensus-mode`).

## Problem

Today the enclave signs any bytes it is given (`Sign`, `SignWith`, `SignDigest`,
`SignDigestWith`). Policy and the high watermark are enforced only by Signatory on the
parent instance. On Nitro, only the parent can reach the enclave's vsock. But the parent is
exactly the component the deployment does not trust with the key. If it is compromised, the
attacker can have the enclave sign two different blocks or attestations at the same level and
round. That is a double sign, and the baker is slashed.

Consensus mode makes the enclave itself refuse to sign anything except consensus payloads
strictly above its watermark. The parent cannot change that.

## Sealed key format

Currently: `KMS-encrypt(CBOR(PrivateKey))`.

New, versioned: `KMS-encrypt(CBOR(SealedKey))`

```rust
enum SealedKey {
    V1 { key: PrivateKey, policy: Policy },
}
enum Policy {
    Unrestricted,                       // legacy behaviour
    Consensus { chain_id: [u8; 4], wm_key_salt: [u8; 32] },
}
```

- The policy is chosen at generation (`Generate`/`GenerateAndImport` take an optional
  `Policy`) and sealed with the key. Because only the enclave can decrypt, the parent can't
  strip or change it.
- A blob that decodes as a bare `PrivateKey` (legacy format) is treated as `Unrestricted`. A
  key generated in consensus mode never exists in the legacy format, so the parent can't
  downgrade it.
- `ImportUnencrypted` can only create `Unrestricted` keys. If the parent has the plaintext key,
  the enclave can't protect it anyway.

## Signing rules for `Consensus` keys

- `Sign`, `SignWith`, `SignDigest` and `SignDigestWith` are **refused**.
- The new `SignConsensus { handle, message }` call parses `message`:

| Magic | Kind | Layout after magic (big-endian) |
|---|---|---|
| `0x11` | block | chain_id(4) · shell header: level(i32) proto(u8) predecessor(32) timestamp(i64) validation_pass(u8) operations_hash(32) fitness(dyn) context(32) · protocol data |
| `0x12` | preattestation | tz4 (only supported type): chain_id(4) · branch(32) · tag(u8 = 40) · level(i32) · round(i32) · block_payload_hash(32), exactly 78 bytes |
| `0x13` | attestation | tz4: chain_id(4) · branch(32) · tag(u8 = 41) · level(i32) · round(i32) · block_payload_hash(32), exactly 78 bytes, with or without DAL |

  - The block round is the last 4 bytes of the Tenderbake fitness, matching Octez and gotez's
    `GetRoundFromTenderbakeBlock`.
  - `chain_id` must equal the sealed policy's chain ID.
  - Any other magic byte, tag, trailing data or length mismatch is refused.
- Watermark rule, per kind (block / preattestation / attestation), matching Signatory's
  `Watermark.Validate`: sign if `(level, round)` is strictly greater than the stored value, or
  if the request is byte-identical to the last one signed (same digest). Otherwise refuse.

## Persisting the watermark (two-phase)

The enclave keeps the watermark in memory, but memory doesn't survive restarts. So every
advance is persisted by the parent before the signature is released:

1. `SignConsensus` checks the rules, computes the signature and keeps it **pending**. It
   returns a `WatermarkRecord { key_id, epoch, seq, kind, level, round, digest, mac }`. The
   `mac` is HMAC-SHA256 under `wm_key = HKDF(private key bytes, wm_key_salt, "tee-signer wm v1")`,
   so only the enclave can produce or verify a record.
2. The parent (Signatory) writes the record to DynamoDB with a conditional write on
   `seq = previous seq` and reports `CommitWatermark { handle, seq }`.
3. Only then does the enclave release the signature and make the new watermark current. If the
   commit never arrives, the pending signature is dropped. The watermark stays advanced in
   memory (fail closed).

## Startup

After `Import` of a consensus key, the handle is **locked**. The parent must call
`LoadWatermark { handle, records }` with the latest stored record for each kind. The enclave
verifies the MACs and adopts them. It then emits a fresh record with `epoch + 1`, which the
parent must commit conditionally. Signing is unlocked only after that commit succeeds. A second
enclave started with the same key can't commit (its `seq` is stale), so it never unlocks.

If there are no records at all (first boot after generation), the enclave accepts that only if
the handle came from `GenerateAndImport` in this same session. Otherwise it stays locked.

## Open questions

1. ~~BLS (tz4) payload format~~ **Resolved (mainnet, PsUshuai, 2026-11-21).** Octez's
   `Operation_repr.Encoding.Bls_mode` (`bls_mode_unsigned_operation`) drops the slot, "to ensure that
   all delegates sign the same message, which is required for BLS proof of possession aggregation".
   tz4 keys sign exactly 78 bytes, with the BLS POP ciphersuite and no pre-hash (tee-signer `SigningVersion::V2`):
   - preattestation: `0x12 · chain_id(4) · branch(32) · 40 · level(i32) · round(i32) · block_payload_hash(32)`
   - attestation: `0x13 · chain_id(4) · branch(32) · 41 · level(i32) · round(i32) · block_payload_hash(32)`
   - **With DAL content, the consensus key and the companion key both sign the same tag-41 message.** The DAL
     bitset is not in the signed bytes. The baker aggregates `sig = sig_consensus + z·sig_companion` with
     `z = LE(blake2b-256(consensus_pkh ‖ companion_pkh ‖ op ‖ bitset))` (`Dal_dependent_signing`). That
     happens in the baker, not the signer.
   - Evidence: an octez-signer log from a tz4 consensus + companion baker (every request 78 bytes, two
     `0x13` requests per attestation), and live mainnet signatures that verify (single-key, and DAL with
     the weighted aggregate key). `signer_core/testdata/tz4_consensus_vectors.json` holds 6 vectors. The
     single-key ones are checked by `crypto::bls::mainnet_vectors`. Gap: no vector yet with a non-zero
     DAL bitset (all mainnet samples had bitset 0).
   - Parser consequence: a tz4 consensus *or companion* key accepts only these two 78-byte forms (plus
     blocks, consensus key only). Level and round are at bytes 38 and 42. The companion key keeps its own
     watermark, with the same rules.
2. ~~DAL companion key~~ Resolved: it signs the same tag-41 attestation bytes as the consensus key (see 1). It gets its own watermark.
3. **Safety margin** after an unclear restart (spec §7.3): optionally refuse levels below
   `stored_level + N` on the first sign after `LoadWatermark`.
4. **Signatory side**: the matching change in `drchrispinnock/signatory` (Nitro vault calls
   `SignConsensus`/`CommitWatermark`, stores records in a new DynamoDB table with conditional writes).

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
| `0x12` | preattestation | tz1–3: chain_id(4) · branch(32) · tag(u8 = 20) · slot(u16) · level(i32) · round(i32) · block_payload_hash(32). **tz4: same without slot, tag 40 (verified, see open question 1)** |
| `0x13` | attestation | chain_id(4) · branch(32) · tag(u8 = 21 / 23 with DAL) · slot(u16) · level(i32) · round(i32) · block_payload_hash(32) [· dal content] |

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

1. **BLS (tz4) payload format: partly verified (mainnet, PsUshuai, 2026-11-21).**
   A real octez-signer log for a tz4 consensus + companion key pair shows that **every** request
   is 78 bytes: preattestations (magic `0x12`), attestations (`0x13`, consensus key) and
   companion-key requests (`0x13`). The tz1-style layout would be 80 bytes, so BLS keys sign
   **without the slot**.
   - **Preattestation, verified** against a live mainnet signature from that key (BLS POP ciphersuite):
     `0x12 · chain_id(4) · branch(32) · 0x28 · level(i32) · round(i32) · block_payload_hash(32)`.
     The tag is **40 (`0x28`)**, not the operation tag 20, so the BLS signing encoding uses its own tags.
   - **Attestation: not yet verified.** Each attestation produces two signing requests (consensus
     key and companion key), and the on-chain signature appears to be their aggregate, so the
     consensus-key message alone doesn't verify. Expected (unconfirmed):
     `0x13 · chain_id · branch · tag(41 or 43?) · level · round · block_payload_hash`.
     The companion key's 78-byte payload is unknown. Next step: take the encodings from the Octez
     source and check with `AggregateVerify([consensus_pk, companion_pk], [m1, m2], sig)`.
   - Implication for the parser: accept only the 78-byte BLS forms for tz4 keys. Level and round are
     at the same offsets (38 and 42) in all of them.
2. **DAL companion key**: which payloads it signs, and whether it needs its own watermark kind.
3. **Safety margin** after an unclear restart (spec §7.3): optionally refuse levels below
   `stored_level + N` on the first sign after `LoadWatermark`.
4. **Signatory side**: the matching change in `drchrispinnock/signatory` (Nitro vault calls
   `SignConsensus`/`CommitWatermark`, stores records in a new DynamoDB table with conditional writes).

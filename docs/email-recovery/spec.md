# Email recovery: statement binding and the email-guardian interface (v1)

**Status: normative, version 1.** This document specifies how control of an
email inbox becomes one guardian approval in Perch's account recovery: what
the recovery email must contain, how the account commits to the address,
what the zero-knowledge circuit proves and exposes, how DKIM keys are
identified and registered, what the per-account email-guardian contract
checks, where one-factor safety is enforced, and which recovery events drive
alerts. Every later component (the circuit, the key registry, the browser
prover, the alert service, the formal model, the paper) builds against it.

Perch is used unchanged. Its recovery is specified in
`vendor/perch/docs/recovery/spec.md` (cited here as **Perch §N**) and its
statement encoding in `vendor/perch/docs/recovery/statement.md` (**Perch
statement.md**).

Keywords **must**, **must not**, **may** are requirements on the component
named in the sentence. Each requirement is marked with what backs it today:

| Mark | Meaning |
| --- | --- |
| **[built, tested]** | Implemented in this repository and pinned by the named tests. |
| **[measured]** | A figure read from a test run in this repository. |
| **[Perch]** | Enforced by Perch's deployed contracts; read from Perch's spec and code. |
| **[specified]** | Normative here, not yet built. The component that will build it is named. |
| **[assumed]** | A cryptographic or operational assumption (see "Assumptions"). |

## Contents

1. Overview
2. Conventions
3. The recovery statement
4. The recovery email
5. Enrollment
6. Circuit public inputs and obligations
7. DKIM key identity, registry, and pin
8. The email-guardian contract
9. One-factor safety and policy rules
10. Alert hook points
11. Properties and their obligations
12. Measurements
13. Open questions

## 1. Overview

| Party | Holds | Role |
| --- | --- | --- |
| User | Their inbox, `account_code`, a new passkey | Sends one email per approval; proves it in the browser |
| Mail provider | The DKIM signing key for its domain | Signs the user's outgoing mail; learns nothing about the attempt (§4.2) |
| Email guardian | `C`, the registry, the pin, the controller, the account, allowed actions, the verifier | One per account; counts as one Perch guardian (§8) |
| Perch controller | The account's recovery configuration and attempts | Collects guardian approvals, enforces quorum, delay, cancellation [Perch] |
| DKIM key registry | A Merkle tree of `(domain, key_hash)` leaves, a k-of-n multisig, an attester set | Says which key-tree roots are acceptable now (§7.3, §7.6) |
| DNS attesters | Ed25519 signing keys | Sign what a provider's DKIM key record publishes (§7.5) |
| Proof verifier | The email circuit's verification key | Perch's UltraHonk verifier behind Perch's `ProofVerifierInterface` (§8.4) |
| Alert service | A keyed lookup from account to alert channels | Notifies the user when the account's recovery state changes (§10) |

**Enrollment** (while the owner still holds a working passkey): the wallet
draws `account_code`, the user sends an enrollment email, the wallet reads the
exact `From` address from it, computes `C`, deploys the account's email
guardian, and applies a document that lists the guardian in the account's
`recovery.mode.guardians` (§5).

**Recovery**: anyone opens a Perch attempt (`begin_lost_key`). The wallet reads
the attempt's statement from the controller, the user sends a recovery email
whose Subject carries a blinded copy of the statement digest (§4), the browser
proves the email (§6), and the wallet submits `submit_guardian` with the
proof inside the guardian's authorization entry. The controller calls
`guardian.require_auth_for_args((digest,))`; the guardian's `__check_auth`
runs the checks of §8.3 and the approval is recorded as one guardian vote.
Quorum, delay, cancellation, and completion are Perch's, unchanged.

## 2. Conventions

- `||` is concatenation; integers are unsigned big-endian unless stated;
  strings are their ASCII bytes with no terminator.
- `r` is the BN254 scalar field modulus
  `0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001`.
  A **field element** is an integer in `[0, r)`, written as 32 big-endian
  bytes.
- `P2(x_1, ..., x_n)` is Noir's `Poseidon2::hash([x_1, ..., x_n], n)` from
  `noir-lang/poseidon` v0.2.0, the hash Perch's circuit and the
  `soroban-poseidon` host function share (Perch §13.3).
- `split(x)` for a 32-byte value `x` is Perch's `split_hi_lo`:
  `hi = 0^16 || x[0..16]`, `lo = 0^16 || x[16..32]`, each a field element
  below `2^128`.
- `pack(bytes, max)` turns `1 ≤ len(bytes) ≤ max` bytes into field elements:
  right-pad with `0x00` to `max` bytes, cut into `max / 31` chunks of 31
  bytes, and read each chunk as a big-endian integer (below `2^248`, so
  always a field element). The length is always hashed alongside, so padding
  is unambiguous.
- `hex(x)` is the 64 lowercase hexadecimal characters of the 32-byte
  big-endian encoding of field element `x`.
- Ledger counts assume 5-second ledgers where durations are given in days
  (Perch §4 "Timing"): 1 day = 17,280 ledgers, 72 hours = 51,840, 7 days =
  120,960.

**Domain tags.** Each tag is `BE(sha256(label)) mod r`, the rule Perch's own
tags follow (Perch statement.md). The values below are pinned by
`contracts/email-guardian/src/test.rs::spec_domain_tags_follow_the_label_rule`,
which recomputes them and Perch's `DOM_AUTH` from their labels **[built,
tested]**.

| Tag | Label | Value |
| --- | --- | --- |
| `DOM_COMMIT` | `nido/email-recovery/v1/commit` | `28c44578265e026b7cecaa4b01b79fef9a1d1e4340e270596de3a724f044ee56` |
| `DOM_BLIND` | `nido/email-recovery/v1/blind` | `2e13b680b3b2cbdab71f094fdf34f9ccd940c01ac6158ebc826ee5bdb05d0726` |
| `DOM_ENROLL` | `nido/email-recovery/v1/enroll` | `2bfe80f315441c3aadf9e7de0ab78fae545af772c0671cf5a512eb1ae713c9e7` |
| `DOM_KEY` | `nido/email-recovery/v1/key` | `1f6d4c7ed15d3b9480457cf9ff55d0ffff201158605d66399703659bf4d765f5` |
| `DOM_LEAF` | `nido/email-recovery/v1/leaf` | `1ddd7b4c7e2eba95d7da44139642c575589aa685188088b0555d3d4fbb5b1f7e` |
| `DOM_PIN_SALT` | `nido/email-recovery/v1/pin-salt` | `03d73ecb3a706d8271405c0c77fb8020c22717b7db10c5eb91f480ea1456bff6` |

The `nido/email-recovery/v1/` labels are distinct from every Perch label
(`perch/recovery/zk/v2/...`), so no value computed under one scheme is a
value of the other.

## 3. The recovery statement

The email factor approves exactly Perch's `RecoveryStatement` (Perch §4) and
nothing else. There is no email-specific statement. The guardian authorizes
`digest = sha256(encoding)`, the circuit binds `digest`, and the guardian
receives the encoding itself and checks it (§8.3).

### 3.1 The four bound items

| Item | Carried by (Perch statement.md offsets) | How the email factor binds it |
| --- | --- | --- |
| **Account** | `account` contract id, bytes 58..90 | The guardian requires it to equal its own account (§8.3 check 5). It also enters the digest. |
| **New key** | Lost-key / compromise: `replacements_hash` (bytes 246..278) commits to the replacement credentials (Perch statement.md "Replacement set"), and `target_doc_hash` (bytes 214..246) to the derived target document. Reconfigure: the new `config_hash` (bytes 175..207). Upgrade: the `wasm_hash` (bytes 182..214). | Through the digest, which the circuit binds in the Subject (§4.2, §6.2 C5). |
| **Nonce** | Lost-key / compromise / cancel: `attempt_id` (bytes 174..182), never reused per account (Perch §6.3 T1); cancel also binds the attempt's own statement digest (bytes 182..214). All actions: `config.epoch` (bytes 122..130), which every configuration change and completion bumps (Perch §3.3). Upgrade: `request_id` (bytes 174..182). | Through the digest. The controller counts each guardian once per attempt and domain (Perch §6.3 T2) and once per change digest (Perch §5). |
| **Expiry** | `timing.valid_until_ledger`, bytes 170..174, a ledger sequence number. | The guardian refuses when the current ledger is past it (§8.3 check 8); the controller applies the same bound (Perch §4 "Freshness"). |

All four items are bound with Perch as it is. Two consequences of using
Perch's statement as the single source:

- **Expiry is a ledger sequence, not a wall-clock time.** Perch's statement
  carries no timestamp field (Perch §4 "Timing"), so neither the guardian nor
  the circuit compares a timestamp. The DKIM `t=` tag is not used either
  (§4.4).
- **The action is inside the digest.** The Subject phrase is the same for
  every action (§4.2), and the circuit needs no action input. The guardian
  reads the action from the statement bytes and checks it against its
  allowed set (§8.3 check 6).

### 3.2 Digest limbs

`digest_hi, digest_lo = split(digest)`, exactly as Perch's ZK projection
splits it (Perch statement.md "ZK projection").

## 4. The recovery email

### 4.1 Envelope

| Element | Requirement |
| --- | --- |
| Sender | The enrolled inbox, sending directly from its provider. Mail that passes through a list or forwarder that rewrites headers fails DKIM and cannot be proven. |
| Recipient | `RECOVERY_INBOX`, one fixed address per deployment, published by the wallet. Nothing about the user is needed to start recovery. The circuit does not bind the recipient (§4.4). |
| Subject | Exactly the bytes of §4.2. |
| Body | Unconstrained. The circuit does not read it (§4.4). |

The wallet should open the user's mail client with a `mailto:` link that
fills in the recipient and the exact Subject, so the user types nothing.

### 4.2 Subject

```text
Subject: APPROVE NIDO ACCOUNT RECOVERY <hex(T)>

T = P2(DOM_BLIND, digest_hi, digest_lo, rho)
```

- The phrase is the 30 bytes `APPROVE NIDO ACCOUNT RECOVERY ` (with its
  trailing space), followed by the 64 characters of `hex(T)`. Nothing may
  precede or follow; a `Re:` prefix or any other byte makes the email
  unprovable.
- `rho` is a fresh field element per email: 31 bytes from a cryptographically
  secure generator, read big-endian (so `rho < 2^248`). It never leaves the
  browser that builds the proof.
- After relaxed header canonicalization (RFC 6376 §3.4.2) the signed field is
  `subject:APPROVE NIDO ACCOUNT RECOVERY <hex(T)>`. A provider that folds the
  long line can fold only at a space; unfolding and the reduction of
  whitespace runs to one space restore the same bytes.

**Why blinded.** Every statement and its digest are public (the controller's
`statement` view). With `digest` in the Subject in the clear, the mail
provider could match the email to the account and attempt. With `T`, it sees
a value that, modelling `P2` as a random function, is independent of
`digest` for anyone who does not know `rho`. The provider still learns that
the user sent a Nido recovery approval at that time.

### 4.3 DKIM requirements

The circuit accepts an email only under all of the following (RFC 6376
section numbers in brackets):

1. One `DKIM-Signature` header field is selected: the one whose `d=` is
   aligned with the `From` domain (rule 6). Other signatures on the message
   (some providers add a second one) are ignored.
2. `v=1`, `a=rsa-sha256` [§3.5]; the RSA modulus has exactly 2048 bits and
   the public exponent is 65537.
3. Header canonicalization is `relaxed` [§3.4.2] (`c=relaxed/relaxed` or
   `c=relaxed/simple`). `simple` header canonicalization is refused.
4. `h=` names `from` and `subject` [§3.5, §5.4].
5. The signed data is the canonicalized header fields `h=` selects, in `h=`
   order, each instance chosen from the bottom of the header block upward
   [§5.4.2], each ended by CRLF, followed by the canonicalized
   `DKIM-Signature` field with its `b=` value deleted and no trailing CRLF
   [§3.7]. The circuit works on exactly these bytes: it
   takes them as input, hashes them, and reads `From` and `Subject` only
   from them. A header field outside the signed data has no effect.
6. The signed data contains exactly one `from` field and exactly one
   `subject` field. (Naming a field in `h=` more often than it occurs, which
   providers do to prevent later additions, contributes nothing to the
   signed data [§5.4.2] and is accepted.)
7. `lowercase(d=)` equals the lowercase domain of the `From` address
   (§4.5) and equals the domain of the registry leaf the key is proven
   against (§7.2). The registry only holds leaves for allowlisted domains
   (§7.3).
8. The signature value `s` satisfies `s < n`, so each email has exactly one
   accepted signature encoding.

### 4.4 What is not bound

| Item | Why it is not bound |
| --- | --- |
| `To:` and the recipient | Not every launch provider's `h=` covers `To:` (Outlook.com's signatures do not). An email to any recipient is equally good evidence of inbox control. |
| The body, `bh=`, `l=` | The approval needs nothing from the body, so the circuit neither reads nor hashes it. The signature still covers the whole signed header block, including the `DKIM-Signature` field. |
| `t=`, `x=` | Not every launch provider sets `t=`. Freshness comes from the statement's `valid_until_ledger` and its single-use attempt id (§3.1). |

### 4.5 The `From` grammar

The value of the single signed `from` field (after relaxed canonicalization,
so without leading or trailing whitespace) must have one of two forms:

```text
from-value   = addr-spec
             / display-name "<" addr-spec ">"      ; ">" is the last byte
display-name = *( %x20-3B / %x3D / %x3F-7E )        ; printable ASCII except "<" and ">"
addr-spec    = local-part "@" domain
local-part   = atom *( "." atom )                   ; RFC 5322 dot-atom, no quoting
atom         = 1*( ALPHA / DIGIT / "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+"
                   / "-" / "/" / "=" / "?" / "^" / "_" / "`" / "{" / "|" / "}" / "~" )
domain       = label *( "." label )                 ; LDH labels, at least two
label        = ALPHA / DIGIT / ALPHA *( ALPHA / DIGIT / "-" ) ( ALPHA / DIGIT )
```

- If the value contains `<`, it contains exactly one `<` and exactly one `>`,
  `>` is its last byte, and the address is the bytes between them. Otherwise
  the whole value is the address. No input has two candidate addresses.
- Quoted local parts, comments, groups, and address lists are refused.
- `1 ≤ len(addr-spec) ≤ 124` bytes (`ADDR_MAX`).
- The address is used **exactly as these bytes**: case, dots, and `+` tags
  are preserved, and nothing is normalized.

## 5. Enrollment

### 5.1 `account_code`

`account_code` is 16 bytes (128 bits) from a cryptographically secure
generator, read big-endian as a field element. The wallet draws a fresh one
for every enrollment and never reuses one across accounts or enrollments.
Nido's servers never receive it. Knowing the address and `account_code` is
what lets anyone compute `C`, so `account_code` is what keeps `C` from
linking an address to an account.

### 5.2 The committed address

The address committed is the `addr-spec` of the DKIM-signed enrollment
email's `From` field (§4.5), byte for byte as the provider wrote it. The
wallet never asks the user to type it: the same provider writes the same
`From` on every later email, so the recovery email will open the same `C`.

### 5.3 The commitment

```text
C = P2(DOM_COMMIT, len, a_0, a_1, a_2, a_3, account_code)

(a_0, a_1, a_2, a_3) = pack(addr-spec, 124)      ; four 31-byte limbs
len                  = len(addr-spec)            ; 1..124
```

`C` is a field element, and the guardian refuses `C = 0` and any
non-canonical encoding (§8.2). The domain of the address is inside `C`, so
the "enrolled domain" is the domain of the committed address.

### 5.4 The enrollment email

```text
Subject: ENROLL NIDO ACCOUNT RECOVERY <hex(E)>

E = P2(DOM_ENROLL, account_hi, account_lo, rho_e)
(account_hi, account_lo) = split(account contract id)
```

`rho_e` is drawn like `rho` (§4.2) and kept by the enrolling wallet. The
phrase differs from the recovery phrase, so an enrollment email can never
satisfy the recovery circuit (§6.2 C5). The body may carry the encrypted
`account_code` backup (§5.6).

Before deploying the guardian, the wallet **must** check the enrollment
email locally:

1. The DKIM signature verifies under §4.3, with a key the registry currently
   accepts (or, for a key not yet registered, the key published in DNS,
   which is then pinned, §7.4).
2. `From` parses under §4.5 and its domain is on the allowlist.
3. The Subject is exactly the enrollment phrase with `hex(E)` for this
   account and the wallet's `rho_e`.

The wallet then computes `C` (§5.3) and the pin root (§7.4) and deploys the
guardian (§8.2). Nothing on chain verifies the enrollment email: the owner
enrolling their own recovery is the only party relying on it, and a wrong
`C` disables only that owner's email factor. **[specified]** (browser
enrollment flow).

### 5.5 Listing the guardian

The owner applies a document whose `recovery.mode.guardians` lists the
guardian's address (Perch §3.1). This is an ordinary Perch configuration
change: owner authorization under `Loss`, owner authorization plus the
current condition under `Protected` (Perch §5). Because the guardian is
immutable and its address is in the configuration, changing the enrolled
address, `account_code`, pin, or allowed actions means deploying a new
guardian and replacing the address through that same gate. Before listing
it, the wallet **must** read the guardian's `config()` and check its wasm
hash and every field against what it intended to deploy.

### 5.6 Backing up `account_code`

Recovery needs `account_code`. The wallet offers two backups, and the
circuit is independent of both (it never reads the body).

**(a) Passphrase-encrypted copy in the enrollment email body** (so it sits in
the user's Sent folder):

```text
-----BEGIN NIDO RECOVERY CODE-----
v1.<base64url-no-padding( salt || nonce || ciphertext )>
-----END NIDO RECOVERY CODE-----

key        = Argon2id(password = passphrase, salt, t = 3, m = 65536 KiB, p = 4, tag = 32 bytes)
ciphertext = AES-256-GCM(key, nonce, plaintext = account_code, aad = "nido/email-recovery/v1/code-backup" || account contract id)
```

- `salt` is 16 random bytes and `nonce` 12 random bytes. The Argon2id
  parameters are RFC 9106 §4's second recommended option (64 MiB, 3 passes,
  4 lanes, 128-bit salt, 256-bit tag), sized for phone browsers.
- `ciphertext` is the 16-byte code plus the 16-byte tag, so the encoded
  payload is 60 bytes (80 base64url characters).
- **Passphrase floor:** the wallet generates the passphrase; it is not
  user-chosen. It is five words drawn uniformly from the EFF large wordlist
  (7,776 words), lowercase, separated by single spaces, at least 64.6 bits.
  The Argon2id password is its UTF-8 bytes.
- The provider stores the ciphertext. Without the passphrase it cannot
  recover `account_code`, so it cannot compute `C` and link the inbox to the
  guardian.

**(b) Recovery kit / password manager:** the 16 bytes as 26 characters of
RFC 4648 base32 without padding, shown in groups of four.

**[specified]** (wallet enrollment flow).

## 6. Circuit public inputs and obligations

### 6.1 Public inputs

The circuit has exactly four public inputs, BN254 field elements in this
order. The guardian hands them to the verifier as one 128-byte blob, each
input 32 bytes big-endian (`PUBLIC_INPUTS_LEN = 128`) **[built, tested]**:

| # | Input | Built by the guardian from | Opened in the circuit by |
| --- | --- | --- | --- |
| 1 | `C` | Its configuration | `addr-spec` bytes and `account_code` (C3) |
| 2 | `digest_hi` | `split(digest)`, `digest` = the authorized context argument | `rho` and the Subject (C5) |
| 3 | `digest_lo` | as above | as above |
| 4 | `key_root` | The approval's `key_root`, accepted only as the pin or a registry-accepted root | The RSA modulus, the leaf domain, the leaf index, and the Merkle path (C6) |

The caller supplies none of them directly (§8.3 check 11). There is no
action input, no timestamp, and no nullifier: the action and expiry are in
the digest (§3.1), and the controller, not a nullifier, stops double
counting.

`digest_hi` and `digest_lo` are always below `2^128` because the guardian
builds them with `split`; the circuit needs no range check on them (the same
argument as Perch §13.3).

### 6.2 Private inputs and obligations

Private inputs: the signed header bytes `H` and their length (bounded by the
circuit's `HEADER_MAX`, which must admit every launch provider's signed
header block), the positions of the `From` address, the Subject token, and
the `d=` value within `H`, the signature `s`, the modulus `n` (§7.1),
`rho`, `account_code`, the leaf domain bytes, the leaf index, and the
Merkle siblings.

| Id | Obligation |
| --- | --- |
| C1 | `s < n`, `n` has exactly 2048 bits, and `s^65537 mod n` equals the EMSA-PKCS1-v1_5 encoding of `SHA-256(H)`. |
| C2 | `H` is a well-formed signed header block under §4.3 rules 3 to 6: header fields in relaxed canonical form, each ended by CRLF, then the `dkim-signature` field with an empty `b=` and no trailing CRLF (RFC 6376 §3.7), carrying `v=1`, `a=rsa-sha256`, relaxed header canonicalization, an `h=` that names `from` and `subject`, and a `d=` value. The circuit does not hash any byte outside `H` and zeroes every input byte past `len(H)`. |
| C3 | `H` contains exactly one `from` field; its value parses under §4.5 to `addr-spec`; `P2(DOM_COMMIT, len, pack(addr-spec, 124), account_code) = C`. |
| C4 | `lowercase(domain(addr-spec)) = lowercase(d=) = leaf domain`. |
| C5 | `H` contains exactly one `subject` field, its value is exactly `APPROVE NIDO ACCOUNT RECOVERY ` followed by 64 lowercase hexadecimal characters, and those characters are `hex(P2(DOM_BLIND, digest_hi, digest_lo, rho))`. |
| C6 | `key_hash = P2(DOM_KEY, limbs(n))` (§7.1), `leaf = P2(DOM_LEAF, len(domain), pack(domain, 62), key_hash)` (§7.2), and the Merkle path from `leaf` at the given index reaches `key_root` (§7.2). |

**[specified]** (the circuit, built with Perch's pinned nargo and bb so the
proof is the zero-knowledge UltraHonk flavor Perch's verifier accepts).

## 7. DKIM key identity, registry, and pin

### 7.1 Key hash

```text
key_hash = P2(DOM_KEY, n_0, n_1, ..., n_17)
n        = sum_i n_i * 2^(120 i),   0 ≤ n_i < 2^120      ; little-endian limb order
```

The RSA-2048 modulus is written as 18 limbs of 120 bits, least significant
limb first (the top limb holds the modulus's highest 8 bits). The exponent
is not hashed: the circuit fixes it to 65537. Keys are tracked by this hash,
never by selector name, because a provider may reuse a selector for a new
key. The registry computes `key_hash` itself from the modulus an addition
carries (§7.6) **[built, tested]** (`contracts/dkim-registry/src/hash.rs`;
cross-checked against Noir, §7.6 "Cross-check of the hashing").

### 7.2 Registry leaf and tree

```text
leaf     = P2(DOM_LEAF, len(domain), d_0, d_1, key_hash)
(d_0, d_1) = pack(domain, 62)            ; the DKIM d= value, lowercase ASCII, 1..62 bytes
```

| Parameter | Value |
| --- | --- |
| Depth | 16 (`REGISTRY_DEPTH`, 65,536 leaves) |
| Interior node | `P2(left, right)`, untagged, as Perch's pool (Perch §13.3) |
| Empty leaf | `0` |
| Empty subtrees | `Z_0 = 0`, `Z_{i+1} = P2(Z_i, Z_i)` |
| Leaf index | decomposed in the circuit into 16 little-endian bits; bit `i` set means the node at level `i` is a right child |

A membership proof starts from a leaf the circuit computes itself as the
five-input `DOM_LEAF` hash above, so no interior node or pin salt leaf
(§7.4) can stand in for a key leaf without a `P2` collision, and no empty
leaf can without a `DOM_LEAF` input that `P2` maps to `0`.
`P2`'s initial state is the input count times `2^64`
(`noir-lang/poseidon` v0.2.0, `poseidon2.nr`), so hashes with different
input counts start from different states.

The registry stores this tree with the host's Poseidon2 (`soroban-poseidon`'s
`Poseidon2Sponge::<4, Bn254Fr>`, the sponge Perch's pool uses) and Perch's
empty-subtree table (`perch_zk_primitives::ZERO_HASHES`, whose first 17
entries are `Z_0..Z_16`), so the root it stores is the root the circuit
proves against **[built, tested]**.

### 7.3 Registry root acceptance

The guardian asks one question of the registry:
`is_accepted_root(root) -> bool`, at the current ledger
(`DkimRegistryInterface`, `contracts/email-guardian/src/registry.rs`). The
registry contract (`contracts/dkim-registry`, §7.6) answers it from its own
state as follows **[built, tested]**:

1. **Activation.** A root that adds a key becomes acceptable only when that
   addition executes, and an addition executes only after its timelock:
   51,840 ledgers (72 hours) after the later of its approval and the
   ledger since which at least `attest_threshold` attesters' latest
   observations see the key live in DNS (`attested_at`, §7.5), or 120,960
   ledgers (7 days) after its approval, whichever comes first. Additions are proposed and approved by the
   registry's multisig. The 72-hour path is closed to a key that was ever
   revoked (rule 3).
2. **Grace.** A root superseded at ledger `S` stays acceptable through ledger
   `S + grace_ledgers` inclusive, so a proof generated against the previous
   root still verifies and a key the provider has just retired keeps working
   briefly. The registry keeps at most `MAX_LIVE_ROOTS = 16` roots (the
   current one and those in grace); when more changes than that fall inside
   one grace period, the oldest superseded root loses the rest of its grace.
3. **Revocation.** Revoking a key for compromise refuses, from the ledger the
   revocation executes in, every root that contains the key, grace included.
   It removes the key from the tree if present and stops every addition of
   it proposed before the revocation. A revoked key can return only through
   a new addition proposed after the revocation, approved by the full
   `threshold`, on the 7-day path.
4. Leaves exist only for allowlisted domains (launch: Gmail, Outlook.com and
   Hotmail, iCloud, Yahoo, Proton, Fastmail, GMX and web.de; §7.6
   "Parameters") and only for RSA keys of exactly 2048 bits. The registry
   refuses any other addition (`DomainNotAllowed`, `KeyNotRsa2048`) and
   computes the key hash and the leaf itself.
5. The empty tree's root `Z_16` is never acceptable: no key could be proven
   under it.

"Contains" is exact. For each leaf the registry records the root sequence
numbers it was part of (`LeafRecord.spans`), so a revocation refuses exactly
the roots that held the key and leaves every other root in its grace. Leaf
indices are never reused, so a refused root can never become current again,
even though retiring the only key added since a root restores that root's
value.

`is_accepted_root` reads instance storage only (§7.6 "Storage"). An archived
tree node can delay a governance change, never an approval.

Root churn is low (only governed changes alter the tree), so a grace window
over superseded roots does not have the denial-of-service problem Perch's
pool avoids by keeping every root (Perch §14.1).

### 7.4 Per-account key pin

A guardian may carry one pin, fixed at construction:

```text
pin tree: depth 16, same hashing as §7.2
  leaf 0      = P2(DOM_PIN_SALT, account_code)
  leaf 1..k   = registry-format leaves (§7.2) of the pinned keys, k ≥ 1
  other leaves = 0
pin = { root, valid_until_ledger }
```

- **Additive.** The guardian accepts `key_root` if it is the pin root and
  the current ledger is at most `valid_until_ledger`, or if the registry
  accepts it (§8.3 check 10). The pin covers the window while a key is
  pending in the registry's timelock and keeps the enrolled key usable if
  the registry drops or stops serving it. Ordinarily the pin holds the key
  that signed the enrollment email.
- **Salted.** DKIM keys are public, so an unsalted pin root over one key
  could be matched against every known provider key and reveal the
  provider. Leaf 0 depends on `account_code`; without it the pin root
  reveals nothing about which keys it holds. Leaf 0 cannot serve as a key
  leaf: that would need a `P2` collision across different tags and input
  counts.
- **Built with the registry's hashing.** A wallet builds the pin tree with
  `nido_dkim_registry::hash::Hasher` (`pin_salt`, `leaf`) and
  `nido_dkim_registry::root_of`, the registry's own formulas. The integration
  test `the_pin_path_works_independently_of_the_registry` deploys a guardian
  whose pin holds a key the registry never admitted, and shows the pin
  accepting it, still accepting it after the registry revokes it, and the
  pin root refused once the pin expires **[built, tested]**.
- **Bounded.** The constructor refuses a pin that has already expired or
  whose `valid_until_ledger` is more than `MAX_PIN_LIFETIME_LEDGERS =
  6,307,200` (365 days) past the deployment ledger **[built, tested]**.
- **The revocation bound.** The pin is the one path the registry cannot
  close. If the registry revokes a pinned key for compromise at ledger
  `L_r`, a guardian whose pin tree holds that key still accepts it through
  the pin until its `valid_until_ledger`, at most 6,307,200 ledgers after
  the guardian was deployed, whatever `L_r` is. During that window, forging
  an approval needs the leaked provider key **and** the victim's exact
  address **and** `account_code`, and the approval is still one vote that
  must clear the rest of the quorum and the delay with alerts. The owner
  closes the window early by replacing the guardian with one without the
  pin (§5.5).

### 7.5 DNS attestations

An attester resolves `selector._domainkey.domain` (RFC 6376 §3.6.2.1)
through one or more resolvers, reads the DKIM key record (RFC 6376 §3.6.1),
and signs one observation of it:

| Offset | Length | Field |
| --- | --- | --- |
| 0 | 38 | `TAG = "nido/email-recovery/v1/dns-attestation"` (ASCII) |
| 38 | 32 | `registry`: the registry's contract id |
| 70 | 1 | domain length, 1 to 62 |
| 71 | 62 | domain: lowercase LDH labels, at least two (the `domain` rule of §4.5, lowercase), zero-padded |
| 133 | 1 | selector length, 1 to 63 |
| 134 | 63 | selector: lowercase letters, digits, `-`, `_`, `.`, zero-padded |
| 197 | 32 | `key_hash` (§7.1) |
| 229 | 1 | `observed_live`: `1` if the record publishes the RSA-2048 key with `key_hash`; `0` if the name has no TXT record, its `p=` is empty, or it holds another key |
| 230 | 8 | `observed_at`: Unix seconds, big-endian |
| 238 | 1 | resolver count, 1 to 4 |
| 239 | … | per resolver: length (1 byte, 1 to 64), then an identifier in printable ASCII (`0x21`–`0x7e`), such as `8.8.8.8` |

The encoding is exact: padding bytes are zero and the length is the sum of
the fields, so each observation has one encoding. The attester signs these
bytes with Ed25519 (RFC 8032), and the registry verifies the signature with
the host's `ed25519_verify`, which traps the call on an invalid signature.
The `registry` field binds an attestation to one registry deployment, and
through its contract id to one network. `observed_at` is the attester's wall
clock; the registry compares it with the ledger's close time **[built,
tested]** (`contracts/dkim-registry/src/attestation.rs`).

`attest(id, attester, attestation, signature)` records an attestation
against proposal `id`. Anyone may submit it. The registry refuses it unless:

| Check | Error |
| --- | --- |
| `attester` is one of the configured attester keys | `NotAnAttester` (30) |
| the proposal exists, is not executed, and has not lapsed | `UnknownProposal` (15), `ProposalClosed` (17), `ProposalExpired` (16) |
| the proposal is an addition or a retirement | `NotAttestable` (36) |
| the bytes are one well-formed encoding | `MalformedAttestation` (31) |
| `registry` is this contract's id | `WrongRegistry` (32) |
| the domain and `key_hash` are the proposal's | `AttestationMismatch` (33) |
| `close_time − 86,400 ≤ observed_at ≤ close_time + 300` | `StaleAttestation` (34) |
| `observed_at` is later than this attester's latest recorded observation for this proposal | `AlreadyAttested` (35) |
| the signature verifies | the call traps |

Each attester's latest observation for a proposal is the one that counts: a
newer one replaces it, so an older signed reading (for instance from before
DNS propagation) cannot hold an attester's place. An addition counts latest
observations with `observed_live = 1`; a retirement counts those with
`observed_live = 0`. The proposal's `attested_at` is the ledger since which
the counted observations have numbered at least `attest_threshold`; a newer
observation that drops the count below the threshold clears it, and reaching
the threshold again sets it to that ledger. Every observation is published
(`dns_attested`), so an attester that does not see a proposed key in DNS is
visible to everyone watching.

**The mock.** `crates/dns-attestation-mock` (TEST ONLY, no live DNS) turns a
key record's TXT strings into a signed attestation with test-only Ed25519
keys **[built, tested]**. It follows RFC 6376 §3.2 (tag-lists: a duplicate
tag invalidates the record, unknown tags are ignored), §3.6.1 (`v=DKIM1`
first if present, `k=` defaulting to `rsa`, `p=` base64 with whitespace
ignored, an empty `p=` meaning revoked), and §3.6.2.2 (a record's strings
are concatenated). For `k=rsa` it accepts both encodings of `p=`: the DER
`RSAPublicKey` that §3.6.1's text names, and the DER `SubjectPublicKeyInfo`
that the RFC's own example procedure (Appendix C, `openssl rsa -pubout`)
produces, which reported erratum 6674
(<https://www.rfc-editor.org/errata/eid6674>) notes providers publish. Its
fixtures (`crates/dns-attestation-mock/testdata/`) are records for
throwaway OpenSSL keys in each shape the RFC allows, a blanked record, and
malformed ones. A CLI (`cargo run -p nido-dns-attestation-mock -- attest
...`) prints attestations as JSON for fixtures.

### 7.6 The registry contract

`contracts/dkim-registry` (crate `nido-dkim-registry`, soroban-sdk as the
workspace pins it). One instance per deployment; each guardian names it in
`GuardianConfig.registry`. There is no admin, no setter, and no upgrade
entry point: the wasm imports no host function that deploys or replaces
contract code and exports exactly the entry points below
(`the_registry_has_no_upgrade_path`) **[built, tested]**. Changing a
parameter means deploying a new registry, and a guardian moves to it only by
being replaced through Perch's reconfiguration gate (§5.5), because the
registry's address is fixed in the guardian.

**Construction.** `__constructor(config: RegistryConfig)` refuses
(`DkimRegistryError`) unless:

| Field | Check | Error |
| --- | --- | --- |
| `members: Vec<Address>` | 1 to `MAX_MEMBERS = 20`, distinct | `InvalidMembers` (1) |
| `threshold`, `revoke_threshold` | `1 ≤ revoke_threshold ≤ threshold ≤ members` | `InvalidThreshold` (2) |
| `attesters: Vec<BytesN<32>>` (Ed25519 keys) | 1 to `MAX_ATTESTERS = 20`, distinct | `InvalidAttesters` (3) |
| `attest_threshold` | `1 ≤ attest_threshold ≤ attesters` | `InvalidAttestThreshold` (4) |
| `grace_ledgers` | at most `MAX_GRACE_LEDGERS = 120,960` | `InvalidGrace` (5) |
| `domains: Vec<Bytes>` | 1 to `MAX_DOMAINS = 32`, distinct, each a lowercase domain of 1 to 62 bytes (§4.5 `domain`) | `InvalidDomains` (6) |

The registry starts with the empty tree. Every key, the launch keys
included, enters through a timelocked addition.

**Proposals.** Members propose and approve with `member.require_auth()`. A
proposer's own approval counts, and each member approves once
(`AlreadyApproved`, 18). Calls by anyone else are refused (`NotAMember`,
10).

| Kind | Proposed with | Needs | Takes effect |
| --- | --- | --- | --- |
| Add | `propose_add(member, domain, modulus)`: the 256-byte big-endian RSA modulus; the registry computes `key_hash` (§7.1) | `threshold` approvals, then the timelock of §7.3 rule 1 | `execute(id)`, by anyone, once eligible (`eligible_at(id)`): the leaf is appended at the next index |
| Retire | `propose_retire(member, domain, key_hash)`, for a key in the tree | `threshold` approvals and `attest_threshold` attestations that the key is gone from DNS | `execute(id)`, by anyone: the leaf is emptied; earlier roots keep their grace |
| Revoke | `propose_revoke(member, domain, key_hash)`, for a key in the tree, pending, or never seen | `revoke_threshold` approvals | the approval that reaches the threshold executes it (§7.3 rule 3) |

A proposal lapses `PROPOSAL_LIFETIME_LEDGERS = 518,400` ledgers (30 days)
after it was created: it can no longer be approved, attested, or executed
(`ProposalExpired`, 16). The other refusals are `DomainNotAllowed` (11),
`KeyNotRsa2048` (12), `KeyAlreadyPresent` (13), `KeyNotPresent` (14),
`UnknownProposal` (15), `ProposalClosed` (17), `NotApproved` (19),
`TimelockActive` (20), `KeyRevoked` (21: an addition proposed before its
key's revocation), `TreeFull` (22), and `NotAttested` (23). The codes are
part of the ABI (`contracts/dkim-registry/src/error.rs`).

**Other entry points.** All are permissionless.

| Entry point | Effect |
| --- | --- |
| `attest(id, attester, attestation, signature)` | §7.5 |
| `execute(id) -> root` | as above; returns the new root |
| `is_accepted_root(root) -> bool` | §7.3; extends the instance's TTL when it is below half the network maximum |
| `root()`, `state()`, `config()` | the current root; the root sequence number, next leaf index, next proposal id, and the roots that may still be acceptable; the configuration |
| `proposal(id)`, `eligible_at(id)` | a proposal with its approvals, attestations, and execution; an approved addition's first eligible ledger |
| `leaf(domain, key_hash)`, `leaf_at(index)` | a leaf's index, presence, root spans, and latest revocation; the leaf at an index |
| `siblings(index)` | the 16 siblings of a leaf's path in the current tree: the circuit's witness (§6.2 C6) |
| `key_hash(modulus)` | §7.1, as an addition computes it |
| `version()` | `1` |
| `renew()`, `renew_path(index)` | extend the instance and code, or one leaf's path, siblings, and records, to the network maximum TTL |

**Storage.** Instance: the configuration and the state (current root, root
sequence number, next leaf index, next proposal id, and the live roots: the
current root and those in grace). Persistent: tree nodes below the root
(`Node(level, index)`; a missing node is the empty subtree), leaf records,
the leaf at each index, and proposals. Every write extends its entry to the
network's maximum TTL.

**Events.** Every proposal, approval, attestation, activation, retirement,
and revocation is an event (§10). Topic 0 is the struct name in snake case,
topic 1 the domain (the proposal id for approvals).

| Event | Fields |
| --- | --- |
| `key_proposed` | domain; id, kind, key hash, the full modulus (additions), proposer |
| `proposal_approved` | id; member, approval count, whether the threshold is reached |
| `dns_attested` | domain; id, attester, selector, key hash, `observed_live`, `observed_at`, resolvers |
| `key_activated` | domain; id, key hash, index, new root, previous root, whether the 72-hour path applied |
| `key_retired` | domain; id, key hash, index, new root, previous root, the last ledger the previous root is accepted |
| `key_revoked` | domain; id, key hash, current root, every root the revocation refused |

**Parameters.** Fixed in the contract: the two timelocks, the proposal
lifetime, the attestation age (24 hours) and clock skew (5 minutes), the
bounds above, and `MAX_LIVE_ROOTS = 16`. Set at construction, with these
proposed defaults:

| Parameter | Proposed default | Rationale |
| --- | --- | --- |
| `members`, `threshold` | 5 members, threshold 3 | Two members can be unavailable without stalling an addition, and two compromised or colluding members cannot add a key. Who the members are is open (§13 item 5). |
| `revoke_threshold` | 2 | An emergency threshold below `threshold`: two members can cut off a leaked key at once, or stop a key a threshold of members planted while its timelock runs. Open (§13 item 5). |
| `attesters`, `attest_threshold` | 3 independent operators, threshold 2 | One attester can be down without closing the 72-hour path, and one attester cannot open it alone. |
| `grace_ledgers` | 17,280 (24 hours) | Covers phone proving (up to about two minutes), mail delivery, and a proof made the same day against the previous root. Open (§13 item 5). |
| `domains` | `nido_dkim_registry::LAUNCH_DOMAINS`: `gmail.com`, `outlook.com`, `hotmail.com`, `icloud.com`, `yahoo.com`, `proton.me`, `protonmail.com`, `fastmail.com`, `gmx.net`, `gmx.de`, `web.de` | The launch providers' primary address domains. Each must also be the `d=` its provider signs with (§4.3 rule 7); open per provider (§13 item 6). |

**Tests [built, tested].** `contracts/dkim-registry/src/test.rs` covers
every construction refusal; allowlist and key-size refusals; the key hash
being computed, never supplied (`the_key_hash_is_computed_never_supplied`);
k-of-n approval and member authorization; both timelocks one ledger before
and at their boundary
(`an_attested_addition_activates_after_exactly_72_hours`,
`any_other_addition_activates_after_exactly_7_days`) and where the 72-hour
clock starts; grace expiry; the live-root cap; retirement; revocation
refusing roots in grace, sparing roots without the key, reaching an already
retired key, stopping a pending addition, and the 7-day-only return; every
attestation refusal and malformed encoding; an attester's latest
observation replacing its earlier one and stopping or restarting the
72-hour clock (`an_attesters_latest_observation_counts`); and every event. The
integration tests run the registry from its wasm, fed by the mock:

| Test | What it shows |
| --- | --- |
| `email_guardian.rs::a_key_added_through_the_attested_path_is_refused_before_72_hours_and_accepted_after` | An approval proven against the root a pending addition will produce is refused by the guardian (`UnknownRoot`) one ledger before the 72 hours end, and counted from the ledger the addition executes in |
| `email_guardian.rs::a_revoked_keys_root_is_refused_at_once` | An approval the guardian accepted is refused in the ledger its key is revoked |
| `email_guardian.rs::the_pin_path_works_independently_of_the_registry` | §7.4 |
| `dkim_registry.rs::the_registry_has_no_upgrade_path` | No code-changing host import; exactly the entry points above |
| `dkim_registry.rs::dkim_registry_costs` | §12 |

**Cross-check of the hashing.** `contracts/dkim-registry/vectors/` is a
Noir package that recomputes, with `noir-lang/poseidon` v0.2.0 (the email
circuit's Poseidon2) and code written independently of the contract (limbs
read byte by byte, roots folded level by level), three fixture keys'
`key_hash` and leaves, the roots of the registry's tree after adding them
and retiring one, a pin root, and `Z_16`. It asserts its values, and the
contract's `noir_vectors` test asserts the same values for keys added
through the contract's own proposals. `just dkim-registry-vectors` runs it
with Perch's pinned nargo (1.0.0-beta.9), and CI runs that recipe **[built,
tested]**.

## 8. The email-guardian contract

`contracts/email-guardian` (crate `nido-email-guardian`, soroban-sdk as the
workspace pins it). One instance per account. No admin, no upgrade entry
point, no setter: every field is fixed at construction **[built, tested]**.

### 8.1 Types

```rust
struct GuardianConfig {
    account: Address,          // the one account; a contract
    controller: Address,       // the account's Perch recovery controller; a contract
    commitment: BytesN<32>,    // C (§5.3): canonical, non-zero
    registry: Address,         // DkimRegistryInterface (§7.3); a contract
    key_pin: Vec<KeyPin>,      // zero or one pin (§7.4)
    allowed_actions: u32,      // ALLOW_* bits: bit (action code - 1)
    verifier: Address,         // ProofVerifierInterface with the email circuit's VK
    circuit_id: BytesN<32>,    // sha256 of that VK, as verifier.circuit_id() reports
}
struct KeyPin { root: BytesN<32>, valid_until_ledger: u32 }

// The signature in the guardian's authorization entry.
struct EmailApproval {
    statement: Bytes,          // the Perch statement encoding (207, 214, or 278 bytes)
    key_root: BytesN<32>,      // the key-tree root the proof was made against
    proof: Bytes,              // the zero-knowledge UltraHonk proof
}
```

`ALLOW_LOST_KEY = 1`, `ALLOW_COMPROMISE = 2`, `ALLOW_CANCEL = 4`,
`ALLOW_RECONFIGURE = 8`, `ALLOW_UPGRADE = 16`, `ALLOW_ALL = 31`. The wallet
deploys `ALLOW_ALL` by default (§9.3). An optional member is a zero-or-one
`Vec`, as Perch writes optional members of contract types
(`ReplacementSet::zk_enrollment`).

### 8.2 Construction

`__constructor(config: GuardianConfig)` stores the configuration in instance
storage, extends it and the code to the network's maximum TTL, and refuses
(`EmailGuardianError`, codes in §8.5) unless:

| Check | Error |
| --- | --- |
| `account` is a contract | `AccountNotContract` (1) |
| `controller` is a contract and not the account | `ControllerNotContract` (2) |
| `registry` and `verifier` are contracts | `DependencyNotContract` (3) |
| `commitment` is non-zero and below `r` | `NonCanonicalCommitment` (4) |
| at most one pin; its root below `r`; deployment ledger `≤ valid_until_ledger ≤` deployment ledger + 6,307,200 | `InvalidPin` (5) |
| `allowed_actions` non-zero and within `ALLOW_ALL` | `InvalidAllowedActions` (6) |
| `verifier.circuit_id()` succeeds and equals `circuit_id` | `CircuitMismatch` (7) |

The last check is the wiring check Perch makes when it enrolls a ZK factor
(Perch §3.4): a guardian whose verifier belongs to another circuit could
never approve anything.

### 8.3 `__check_auth`

The controller's `submit_guardian` (lost-key, compromise, cancel) and
`approve_change` (reconfigure, upgrade) call
`guardian.require_auth_for_args((digest,))` (Perch §4 "Binding", §6.3 T2,
§5). The host then calls
`__check_auth(signature_payload, approval: EmailApproval, auth_contexts)`.
The guardian runs these checks in order and returns the first failure:

| # | Check | Error |
| --- | --- | --- |
| 1 | `auth_contexts` is exactly one contract call, on `controller`, with exactly one argument, a 32-byte `digest` | `UnexpectedContext` (10) |
| 2 | `sha256(approval.statement) = digest` | `DigestMismatch` (11) |
| 3 | The statement is a version-2 Perch encoding: domain prefix, version byte `2`, a known action code, and that action's exact length (Perch statement.md) | `MalformedStatement` (12) |
| 4 | Its `network_id` is the ledger's network id | `WrongNetwork` (13) |
| 5 | Its `account` is the guardian's account | `WrongAccount` (14) |
| 6 | Its `controller` is the guardian's controller | `WrongController` (15) |
| 7 | Its action's bit is in `allowed_actions` | `ActionNotAllowed` (16) |
| 8 | The call is the action's entry point: `submit_guardian` for actions 1 to 3, `approve_change` for 4 and 5 | `WrongEntryPoint` (17) |
| 9 | Current ledger `≤ valid_until_ledger` | `StatementExpired` (18) |
| 10 | `key_root < r` | `NonCanonicalRoot` (19) |
| 11 | `key_root` equals the pin root with the current ledger `≤` the pin's `valid_until_ledger`; otherwise `registry.is_accepted_root(key_root)` returns `true` | `UnknownRoot` (20), or `RegistryUnavailable` (21) if the call fails |
| 12 | `verifier.verify_proof(C ‖ digest_hi ‖ digest_lo ‖ key_root, proof)` succeeds, with every input taken from the configuration, the context's `digest`, and the root accepted in check 11 | `ProofRejected` (22) when the verifier refuses the proof, `VerifierUnavailable` (23) when its key does not parse or the call fails |

**Why one guardian per account.** Perch binds guardian addresses into the
account's `config_hash` (Perch §3.2), so everything fixed at the guardian's
address is covered by Perch's reconfiguration gate (§5.5). A guardian shared
by many accounts would need a table from account to commitment, and whoever
could change that table could change an account's email factor without that
gate. And `require_auth_for_args((digest,))` hands the guardian only the
digest: it learns which account the digest is for only from the statement
bytes (check 2), and approves only for its own account (check 5).

**What the guardian does not check, and why that is sound.**

- *The host's `signature_payload`* (the auth entry's nonce, expiration, and
  invocation hash). The proof binds the statement, not one authorization
  entry. Anyone can re-wrap a valid approval in a new entry, and it can
  still authorize only the same digest, which the controller counts once
  (Perch §6.3 T2, §5). A copy submitted first records the same vote the
  original would have, so front-running changes nothing.
- *Quorum, delay, attempt liveness, cancellation, the epoch.* The
  controller's (Perch §5, §6). The guardian could not check them anyway:
  the controller is on the call stack while `__check_auth` runs, and Soroban
  refuses re-entry (Perch D16). The guardian calls only the registry and the
  verifier, never the controller or the account.

`approval.proof`'s length is the verifier's to check.

### 8.4 The verifier

The guardian calls `verify_proof(public_inputs: Bytes, proof_bytes: Bytes)`
through Perch's `perch_recovery_interface::zk::ProofVerifierClient`, the
interface Perch's ZK adapter exposes, and maps Perch's `ProofVerifierError`
as in check 12. The production verifier is a constructorless, immutable
contract that embeds Perch's vendored UltraHonk verifier
(`vendor/perch/vendor/ultrahonk-soroban-verifier`, `UltraHonkZkVerifier`)
with the email circuit's verification key compiled in, exactly as Perch's
adapter embeds its own (`vendor/perch/crates/perch-zk-adapter`), and also
exposes `circuit_id() = sha256(vk)` (`VerifierIdentity`,
`contracts/email-guardian/src/verifier.rs`). **[specified]** (on-chain
verification work, once the circuit's key exists).

### 8.5 Other entry points, storage, and errors

| Entry point | Authorization | Effect |
| --- | --- | --- |
| `config() -> GuardianConfig` | none | read-only |
| `version() -> u32` | none | `1` |
| `renew()` | none | extends the instance and its code to the network maximum TTL; changes nothing else |

The guardian emits no events and stores nothing after construction. Its
error enum is `EmailGuardianError` (`contracts/email-guardian/src/error.rs`);
the codes above are part of its ABI.

**Tests [built, tested].** `contracts/email-guardian/src/test.rs` covers
every construction refusal and every `__check_auth` refusal in §8.3
(including caller-supplied public inputs being ignored: proofs valid for
another commitment, another digest, or another root are refused), the
pin's acceptance window, and parsing of all five statement shapes produced
by Perch's own encoder. It uses a test-only verifier (accepts a "proof"
exactly when it is a SHA-256 tag of the public inputs it receives) and a
test-only registry; the guardian's code path is the production one. The
integration tests (§9.3, §7.6) use the registry contract from its wasm.

## 9. One-factor safety and policy rules

Email is never sufficient alone. Three layers enforce it, each with a
different guarantee.

### 9.1 Perch, on chain [Perch]

- An attempt is authorized only when `quorum` distinct enrolled guardians
  approved its statement (Perch §5, §6.3 T4). The email guardian is one
  address, so it contributes at most one vote per attempt and domain (Perch
  §6.3 T2: `AlreadyCounted`).
- An authorized attempt completes only at
  `L ≥ authorized_at + delay_ledgers`, and `delay_ledgers > 0` (Perch §3.1,
  §6.2, §6.3 T5).
- During the delay the owner can cancel under `Loss` (Perch §6.3 T7) and the
  condition can cancel under `Protected` (T6). Opening an attempt is
  permissionless and grants nothing (Perch D2).

### 9.2 The email guardian, on chain [built, tested]

It approves only its own account's statements, on its own controller and
network, for allowed actions, before expiry, with a proof bound to its own
`C` (§8.3). It cannot see the account's quorum, profile, or delay (§8.3).

### 9.3 Nido's wallet policy [built, tested]

Nido's wallet builds every recovery member through `recoverySpec` in
`packages/passkey-sdk/src/perch/doc.ts`. That builder **must** refuse a
member that breaks any rule below. (`packages/passkey-sdk/src/policyDoc/validate.ts`
is not the place: it mirrors Perch's on-chain validator and must refuse
exactly what that validator refuses.)

1. **One email guardian.** At most one email guardian per recovery member.
   Email is one factor; a second guardian for the same inbox would be a
   second vote for it.
2. **Second alert channel.** A member that lists an email guardian requires
   a second alert channel registered with the alert service (Web Push to a
   passkey device, §10).
3. **Email plus delay.** If the email vote alone authorizes an attempt
   (`guardian-only` mode with `quorum = 1`), the member must use the `loss`
   profile and `delay-ledgers ≥ 120,960` (7 days). In `combined` mode the
   ZK factor is always needed as well, so this case does not arise there.
4. **Allowed actions.** The guardian is deployed with `ALLOW_ALL`. A
   narrower set is refused whenever the email vote is needed to reach the
   quorum (the member's other guardians number fewer than `quorum`),
   because a `Protected` account whose quorum needs the email vote could
   otherwise never reconfigure or upgrade.

The builder tells the email guardian apart by a typed marker, never by its
address: the wallet lists it in `RecoveryChoice.guardians` as
`{ kind: 'email', address, allowedActions }` when it deploys it, and states
the registered second channel as `RecoveryChoice.secondAlertChannel`
(`'web-push'`). The alert service that registers the channel is
**[specified]** (§10). `packages/passkey-sdk/src/perch/recoverySpec.test.ts`
("email guardian rules") pins each rule at its boundary **[built, tested]**:

| Test | What it shows |
| --- | --- |
| `rule 1: accepts one email guardian and refuses a second` | One email guardian is accepted; two are refused |
| `rule 2: an email guardian needs a second alert channel` | With `secondAlertChannel` accepted, without it refused |
| `rule 3: email alone needs the loss profile and a delay of at least 120960 ledgers` | `guardian-only`, quorum 1: delay 120,959 refused, 120,960 and the default accepted, `protected` refused; also with other guardians listed at quorum 1 |
| `rule 3: does not apply when the email vote alone cannot authorize` | Quorum 2, and `combined` with quorum 1, accept `protected` and a 24-ledger delay |
| `rule 4: refuses narrower allowed actions when the quorum needs the email vote` | A narrower set is refused with two other guardians at quorum 3 and in `combined` with quorum 1, accepted with two other guardians at quorum 2; `ALLOW_ALL` is accepted at quorum 3 |
| `leaves configurations without an email guardian unaffected` | Without an email guardian, quorum 1, `protected`, a 24-ledger delay, and no second channel are accepted |

**What each layer guarantees.** On chain, for every configuration: email
approvals alone never complete a recovery without the delay passing, and
with `quorum ≥ 2` (or in `combined` mode) they never authorize one. The
wallet rules add that Nido never produces a configuration in which the
email vote alone authorizes, except under `loss` with a delay of at least 7
days and a second alert channel. The chain accepts any configuration the owner applies, so a
different wallet could build one Nido would refuse.

`crates/integration-tests/tests/it/email_guardian.rs` pins the on-chain part
on Nido's stack (Perch's controller and account from their deployed wasm,
the guardian and the key registry from their wasm, the registry fed by the
DNS attester mock) **[built, tested]**:

| Test | What it shows |
| --- | --- |
| `email_approval_counts_as_exactly_one_guardian_vote` | One email approval is one vote of a 2-of-3 quorum; with one more guardian the attempt is authorized and completes only after the delay |
| `the_same_email_approval_is_not_counted_twice` | Resubmitting the approval in a fresh authorization entry is refused (`AlreadyCounted`) |
| `an_email_approval_cannot_be_replayed_into_another_attempt` | Another attempt's digest, a spliced statement and proof, and the cancel domain are all refused (`DigestMismatch`, `ProofRejected`) |
| `an_email_approval_cannot_be_replayed_into_another_account` | Even with two guardians sharing one `C`, account A's approval does not count for account B |
| `email_approvals_alone_never_complete_a_recovery` | With a 2-of-2 quorum the email vote never authorizes; as the only guardian (quorum 1, `Loss`) it authorizes, but completion waits for the delay, the owner can cancel, and a new attempt needs a new email |
| `email_approval_counts_toward_a_protected_reconfiguration` | Through `approve_change`, the email vote is one vote of a `Protected` reconfiguration quorum |

## 10. Alert hook points

Alerts are driven by the controller's events, filtered by account. Nothing
is written on chain for alerts: no tag, no registration, no event from the
guardian.

| Event (topic 0) | Topic 1 | Alert |
| --- | --- | --- |
| `attempt_authorized` | account | **Required, on every channel:** the account has entered a recovery window; generic text plus the per-attempt verification code |
| `recovery_completed` | account | Required: the account's signers changed |
| `attempt_cancelled` | account | Informational |
| `epoch_advanced` | account | Required: the recovery configuration (guardians, timing, the email guardian itself) changed |
| `change_evidence_recorded` | account | Informational: approvals for a reconfiguration or upgrade are being collected |
| `attempt_begun` | account | Informational and rate-limited: opening an attempt is permissionless, so these can be spammed |
| `attempt_invalidated` | account | None |

Topic 0 is the event struct's name in snake case and topic 1 the account
(`#[contractevent]` with one `#[topic]` field; structs in
`perch-recovery/src/contract.rs`) [Perch].

**Lookup.** The alert service keeps each account's alert channels under

```text
lookup = HMAC-SHA-256(k_alert, "nido/email-recovery/v1/alert-lookup" || account contract id)
```

where `k_alert` never leaves the sealed vault that holds the addresses. The
service computes `lookup` for the account in each event's topic and finds
the record; an observer without `k_alert` cannot list which accounts have
alerts. When email is a recovery factor, a second channel (Web Push to a
passkey device) is required (§9.3 rule 2).
**[specified]** (alert service).

**Registry changes.** The key registry's events (§7.6) concern every
account at once, so they are announced publicly rather than per account.
Every one is emitted **[built, tested]**; the announcements are
**[specified]** (alert service).

| Event (topic 0) | Topic 1 | Announcement |
| --- | --- | --- |
| `key_proposed` | domain | **Required:** a key was proposed for the domain, with its modulus, so anyone can compare it with DNS; for an addition, the earliest ledger it can activate (`eligible_at` once approved) |
| `proposal_approved` | proposal id | Informational: approvals collected; when `approved`, the addition's timelock is running |
| `dns_attested` | domain | Informational; **required** when `observed_live = 0` on an addition: an attester did not see the proposed key in DNS |
| `key_activated` | domain | **Required:** the key is now accepted |
| `key_retired` | domain | Informational: the key leaves acceptance after the grace period |
| `key_revoked` | domain | **Required:** the key and every root holding it are refused |

## 11. Properties and their obligations

### 11.1 Assumptions

| Id | Assumption |
| --- | --- |
| A1 | RSASSA-PKCS1-v1_5 with SHA-256 and 2048-bit moduli is existentially unforgeable, and providers keep their DKIM private keys secret. |
| A2 | SHA-256 is collision resistant. |
| A3 | `P2` is collision resistant, and no input is known that it maps to `0` (the empty leaf); for the hiding claims (privacy, the blinded Subject, the salted pin) it is modelled as a random function. |
| A4 | The UltraHonk proof system with Perch's zero-knowledge flavor is knowledge sound and zero-knowledge, and the verifier contract embeds the email circuit's key. |
| A5 | The registry holds a leaf `(domain, key_hash)` only for a key that domain's operator controls. The registry contract reduces this to its governance (§7.6): a key enters only with `threshold` member approvals, after a public timelock (72 hours if `attest_threshold` attesters vouched it live in DNS, 7 days otherwise) during which `revoke_threshold` members can stop it; revocation is applied when a compromise is known. |
| A6 | `account_code` and `rho` come from a secure generator and stay with the user and the user's browser. |
| A7 | The enrolling wallet is honest at enrollment (it computes `C` and the pin from the real enrollment email). |

### 11.2 Statements

Let `G` be an email guardian with configuration
`(account, controller, C, registry, pin, allowed, verifier)`.

1. **Soundness of the email factor.** If `G.__check_auth` succeeds on
   `(statement S, key_root R, proof)` in the context
   `controller.f((d,))` at ledger `L`, then, except with negligible
   probability, there is an email whose signed header block `H` carries a
   valid DKIM RSA-2048 signature (§4.3) under a key `n` with
   `leaf(domain, key_hash(n))` in the tree with root `R`; `R` is the pin
   root with `L ≤ pin.valid_until_ledger`, or a root the registry accepts at
   `L`; the `From` address of `H` is the address committed in `C`, and its
   domain is the leaf's domain and `d=`; and the Subject of `H` opens to
   `d = sha256(S)`, where `S` names `G`'s account, controller, and network,
   an allowed action, and a `valid_until_ledger ≥ L`. Through `S` the email
   binds the account, the new key (replacements and target, or new
   configuration, or Wasm hash), the nonce (attempt id or request id, and
   the epoch), and the expiry (§3.1).
2. **Privacy.** For any two addresses at allowlisted providers, a guardian's
   on-chain state and every approval it accepts (`C`, the pin root, the
   statements, the roots, the proofs) are computationally indistinguishable
   between the two addresses when `account_code` is uniform and unknown.
   What is revealed: that the account has an email guardian, its allowed
   actions, the time of each approval, and whether an approval used the pin
   or a registry root. Off chain, the provider sees `T` (§4.2), which hides
   `d`.
3. **Replay and front-running resistance.** An approval accepted for digest
   `d` is accepted only in a context naming `d`; `d` fixes one account, one
   network, one controller, one action, and one attempt (or request) id at
   one epoch; and the controller records `G` at most once per attempt and
   domain, or once per change digest. A copy submitted by anyone records
   the same single vote.
4. **One-factor safety.** For every recovery configuration listing `G`: no
   sequence of transactions whose only evidence is approvals by `G`
   completes a recovery before `delay_ledgers > 0` ledgers have passed since
   authorization, and if `quorum ≥ 2` or the mode is `combined`, none
   authorizes an attempt. Under
   Nido's wallet policy, `G` alone reaches the quorum only under `loss` with
   `delay_ledgers ≥ 120,960` and a second alert channel.

### 11.3 Obligation table

Status: **proven** (formal proof), **tested** (this repository's tests),
**specified** (normative, not built), **assumed**. The proofs are Lean
theorems in `research/email-recovery/formal` about a model of the guardian's
checks (§8.3), the circuit relation (C1 to C6), and Perch's controller; the
model's agreement with the contracts is tested, not proven
(`research/email-recovery/formal/README.md`).

| Property | Circuit obligations | Contract obligations (guardian) | Perch obligations | Assumptions | Status |
| --- | --- | --- | --- | --- | --- |
| 1 Soundness | C1, C2, C3, C4, C5, C6 | §8.3 checks 1 to 12; §8.2 wiring check; registry: §7.3 rules 1 to 5 and the same tree hashing as C6 (§7.2, §7.6 cross-check) | Statement construction from controller state (Perch §4) | A1, A2, A3 (collision), A4 (soundness), A5, A7 | Proven from the circuit relation with A4, A5, A7 as hypotheses and A3's breaks named (`EmailRecovery.soundness`); A1 assumed; guardian checks and registry rules tested; registry hashing tested against Noir; circuit specified |
| 2 Privacy | Public inputs are exactly §6.1; nothing else is exposed | Stores `C` and a salted pin root, never an address or key hash; emits nothing | — | A3 (random function), A4 (zero-knowledge), A6 | Noninterference proven (`EmailRecovery.privacy_noninterference`); indistinguishability rests on A3, A4, A6, assumed; guardian storage tested; circuit specified |
| 3 Replay | C5 binds `d` | Checks 1, 2, 5, 6, 8, 12 | One vote per guardian per attempt and domain, or per change digest (Perch §6.3 T2, §5); attempt ids never reused (T1); epochs only grow (§3.3) | A2, A3, A4 | Proven with A2's break named (`EmailRecovery.Perch.email_vote_replay`); tested (unit and integration) |
| 4 One-factor safety | — | The guardian is one address | Quorum (T4), delay (T5), cancellation (T6, T7) | — | Proven over all controller traces (`EmailRecovery.Perch.one_factor_safety`) and for the wallet policy (`one_factor_under_wallet_policy`); on-chain part tested; wallet policy tested (§9.3) |

## 12. Measurements

All figures were read from test runs in this repository; nothing here is a
network measurement.

| Figure | Value | Source |
| --- | --- | --- |
| Guardian wasm, optimized | 32,547 bytes | `just build-contracts` output for `nido_email_guardian.wasm` (local build; the CLI version recorded in the wasm metadata can change it by a few bytes) **[measured]** |
| Registry wasm, optimized | 67,337 bytes | `just build-contracts` output for `nido_dkim_registry.wasm` (same caveat) **[measured]** |
| One `submit_guardian` with an email approval, whole invocation | 2,118,851 instructions; 905,658 bytes of memory; 13 entries read; 2 entries and 1,208 bytes written | `email_approval_plumbing_cost`, `cost_estimate().resources()` **[measured]** |
| The guardian's authorization entry (16,224-byte proof) | 16,784 bytes of XDR | same test **[measured]** |
| `is_accepted_root`, accepted or refused | 565,446 / 568,058 instructions; 286,222 bytes of memory; 2 entries read; nothing written; no events; fee without rent 396 / 398 stroops | `dkim_registry_costs` **[measured]** |
| `propose_add` (computes the key hash over the 2048-bit modulus) | 9,348,283 instructions; 533,605 bytes of memory; 6 entries read; 3 entries and 1,588 bytes written; 744 event bytes; fee without rent 23,723 stroops | same test **[measured]** |
| `approve` | 666,915 instructions; 300,965 bytes of memory; 5 entries read; 2 entries and 492 bytes written; 208 event bytes; fee without rent 10,030 stroops | same test **[measured]** |
| `attest` (parse, checks, Ed25519 verification) | 1,159,121 instructions; 291,157 bytes of memory; 3 entries read; 1 entry and 436 bytes written; 412 event bytes; fee without rent 7,260 stroops | same test **[measured]** |
| `execute` of an addition (the leaf and the 16-level root recomputation) | 22,787,215 instructions; 1,077,800 bytes of memory; 37 entries read; 20 entries and 4,384 bytes written; 348 event bytes; fee without rent 102,659 stroops | same test **[measured]** |
| The approval that executes a revocation (removal, root recomputation, refusals) | 20,051,676 instructions; 883,550 bytes of memory; 39 entries read; 21 entries and 1,944 bytes written; 516 event bytes; fee without rent 103,542 stroops | same test **[measured]** |

The `submit_guardian` figure is a plumbing figure: Perch's controller and
account, the guardian, and the registry run as wasm, but the verifier is
the test-only stand-in, which does no cryptography. It contains no proof
verification. The registry figures are the whole invocation of each entry
point from the registry's wasm (no entry was read from disk, so ledger
bytes read are 0 in every row), with the 3-of-5, 2-of-3 configuration of
`crates/integration-tests/src/email.rs`; `dkim_registry_costs` also asserts
loose ceilings on `is_accepted_root`, `attest`, and the activation. The fee
figures are the SDK's `cost_estimate().fee()`, which prices the measured
resources with a hardcoded snapshot of mainnet fee rates; they are not
network measurements. Rent is left out of them: every registry write extends
its entries to the maximum TTL, so the rent charged depends on the network's
maximum TTL (10,000,000 ledgers in this test ledger) and on how recently an
entry was last extended, and the SDK prices rent above the network's rate on
purpose. Fees on testnet are not measured here.

Real verification cost is measured once the circuit and its verifier exist.
Fee estimation through RPC simulation needs care: Soroban's
recording-mode simulation does not run custom accounts' `__check_auth`
(`vendor/perch/AGENTS.md`), so a simulated `submit_guardian` omits the
guardian's checks and the proof verification.

## 13. Open questions

1. **Key pin semantics.** v1 pins additively, fixed at construction, salted,
   with an expiry. Alternatives: a restrictive pin (only pinned keys,
   registry ignored), which makes a planted registry key useless but stops
   email recovery at every provider rotation until a new guardian is
   deployed; requiring both the registry and the pin, with the same
   rotation problem; a pin the owner can change after deployment, which
   would let anyone holding the owner key and `account_code` pin a key of
   their own and approve without the inbox.
2. **Pin lifetime.** The cap is 365 days (`MAX_PIN_LIFETIME_LEDGERS`).
   Shorter caps narrow the revocation window of §7.4 at the cost of more
   frequent guardian replacement; the wallet's default lifetime within the
   cap is not fixed.
3. **Default allowed actions.** v1 deploys all five actions. Alternatives:
   initiation and cancellation only, or initiation only, with §9.3 rule 4
   preventing a lock-out.
4. **`account_code` backup.** v1 offers the passphrase-encrypted copy in the
   enrollment email and a recovery kit. Alternatives: the code in plain text
   in the enrollment email (best recoverability; the provider can compute
   `C` and link the inbox to the account), or a recovery kit only (no copy
   at the provider; lost if the kit is lost).
5. **Registry parameters.** The registry is built with the defaults of §7.6;
   each is a constructor parameter.
   - *Grace period.* Built with 17,280 ledgers (24 hours), capped at
     120,960. Alternatives: 120,960 ledgers (7 days), which strands fewer
     proofs made against a previous root but keeps a key its provider has
     blanked in DNS acceptable for a week unless it is revoked; or 720
     ledgers (1 hour), which shortens that window but can strand a user whose
     proof was made against the previous root.
   - *Revocation threshold.* Built with an emergency threshold of 2 of 5
     members, paired with the rule that a revoked key returns only through a
     new full-threshold addition on the 7-day path. Alternative: the full
     threshold (3 of 5), under which two members cannot block a provider's
     live key, and also cannot stop a key a threshold of members planted
     during its timelock or cut off a leaked key without a third approval.
   - *Who.* The five members, the three attester operators, and the
     resolvers each attester queries are not named.
6. **Provider details.** The exact domain allowlist per launch provider
   (for example whether secondary domains sign with their own `d=`), the
   `HEADER_MAX` bound, and whether each provider's stored or received copy
   keeps its `DKIM-Signature` are to be confirmed with provider-format
   fixtures in the circuit work.
7. **`RECOVERY_INBOX`.** The fixed recipient address and how its mail
   reaches the browser (sealed inbound or `.eml` import) are not fixed here.
8. **Per-attempt verification code.** How the alert service derives the
   code an `attempt_authorized` alert carries, and how the recovering
   wallet shows the same code, is the alert service's to specify.
9. **On-chain enrollment proof.** v1 checks the enrollment email in the
   wallet only (§5.4). A guardian constructor that verifies a proof of the
   enrollment email would make `C` verifiable by third parties, at the cost
   of a second circuit.
10. **Guardian deployment.** Whether guardians are deployed through a Nido
    factory (fixing the wasm hash and the address derivation) or directly by
    the wallet.
11. **Wallet policy.** The rules of §9.3 are built in `recoverySpec` and
    tested (§9.3 lists the tests). They bind Nido's wallet only: the chain
    accepts any configuration the owner applies, and the second alert
    channel is an input the alert service, not yet built, will back.
12. **Address and domain bounds.** `ADDR_MAX = 124` and the 62-byte leaf
    domain cover the launch providers. Custom domains would need larger
    bounds, which change `C`'s packing and the leaf format (a new version).

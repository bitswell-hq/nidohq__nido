# Email recovery: statement binding and the email-guardian interface (v1)

**Status: normative, version 1.** This document specifies how control of an
email inbox becomes one guardian approval in Perch's account recovery: what
the recovery email must contain, how the account commits to the address,
what the zero-knowledge circuit proves and exposes, how DKIM keys are
identified and registered, what the per-account email-guardian contract
checks, where one-factor safety is enforced, which recovery events drive
alerts, and how the alert service delivers them without its operator
reading an address. Every later component (the circuit, the key registry,
the browser prover, the alert service, the formal model, the paper) builds
against it.

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
10. Alerts
11. Properties and their obligations
12. Measurements
13. Open questions

## 1. Overview

| Party | Holds | Role |
| --- | --- | --- |
| User | Their inbox, `account_code`, a new passkey | Sends one email per approval; proves it in the browser |
| Mail provider | The DKIM signing key for its domain | Signs the user's outgoing mail; the Subject's content names no attempt (§4.2), though its timing can (§10.7) |
| Email guardian | `C`, the registry, the pin, the controller, the account, allowed actions, the verifier | One per account; counts as one Perch guardian (§8) |
| Perch controller | The account's recovery configuration and attempts | Collects guardian approvals, enforces quorum, delay, cancellation [Perch] |
| DKIM key registry | A Merkle tree of `(domain, key_hash)` leaves, a k-of-n multisig, an attester set | Says which key-tree roots are acceptable now (§7.3, §7.6) |
| Enclave-image registry | Approved enclave measurements, a fixed multisig, a 14-day timelock | Says which enclave images may receive the alert vault's key (§10.4) |
| DNS attesters | Ed25519 signing keys | Sign what a provider's DKIM key record publishes (§7.5) |
| Proof verifier | The email circuit's verification key | Perch's UltraHonk verifier behind Perch's `ProofVerifierInterface` (§8.4) |
| Alert service | A host that watches the controller and reads its state, and a sealed vault holding a keyed lookup from account to alert contacts | Notifies the user when the account's recovery state changes or its email guardian votes (§10) |

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
- **Two clocks.** The windows this design adds are measured on ledger close
  time (`env.ledger().timestamp()`, Unix seconds): the registry's timelocks,
  grace period, and proposal lifetime (§7.3, §7.6), the key pin (§7.4), and
  the enclave-image registry's timelock (§10.4). Perch's windows are ledger
  counts and Perch is used unchanged: the recovery delay, the evidence
  window, and the statement's expiry (Perch §4 "Timing"). Where a ledger
  count stands for days, it is at the 5-second target close time testnet and
  mainnet set (1 day = 17,280 ledgers, 7 days = 120,960); the wallet sizes
  the one ledger count that carries a security floor from the network's
  current target (§9.3 rule 3). §11.1 A9 states what each clock assumes.

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
  the circuit compares the statement with a timestamp. The DKIM `t=` tag is
  not used either (§4.4).
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
Because the body is unconstrained, the wallet's `mailto:` link prefills it
with a line for a user who is being talked into sending the email: *If
anyone asked you to send this email, stop. Nido never asks for this.*
(`NOBODY_ASKS_LINE`, `recoveryEmail` in
`packages/frontend/src/lib/recovery/emailModel.ts`) **[built, tested]**.

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

Two rules on the tag list itself [§3.2, §3.5, §6.1.1]:

- The six tags the circuit reads, `v=`, `a=`, `c=`, `d=`, `h=` and `b=`,
  each appear exactly once. The values of `v=`, `a=`, `c=`, `d=` and `b=`
  follow `=` directly and end at `;` or the end of the field, so whitespace
  around their `=` or before their `;` is refused, although RFC 6376 §3.2
  allows it. In `h=`, whitespace around the entries is accepted (Fastmail
  folds right after `h=`), but not between the name and `=`. This is a
  completeness limit: among the 5,327 signatures on real launch-provider
  posts of §12, whitespace in these places occurs in Fastmail's `h=`, which
  the circuit accepts (its mock reproduces the fold), and in
  `d= messagingengine.com`, Fastmail's second signature,
  which the circuit refuses for its `d=` in any case (rule 7).
- Every other tag is located, so no value is ever read from inside one, but
  not validated. The circuit accepts a field that RFC 6376 tells verifiers to
  ignore for a defect in a tag it does not read: an empty tag-spec, a tag
  without `=`, a missing or repeated `s=`, a missing `bh=`, a malformed `l=`
  or `i=`, an `i=` outside `d=`, a `q=` without `dns/txt`. This does not weaken the proof: the field
  is part of the signed data, so only the holder of the signing key can
  write it (A1a).

Both rules are **[built, tested]**: the grammar-based fuzzing in
`research/email-recovery/eval/parser/` reaches each case and compares the
circuit with mailauth's strict RFC 6376 verifier.

### 4.4 What is not bound

| Item | Why it is not bound |
| --- | --- |
| `To:` and the recipient | Not every launch provider's `h=` covers `To:` (Outlook.com's signatures do not). An email to any recipient is equally good evidence of inbox control. Binding `To:` to `RECOVERY_INBOX` would not stop a social engineer either (§11.4): the attacker opens the attempt with the real recovery page and registers its own sealed-inbound value, so the email it asks the victim to send already goes to `RECOVERY_INBOX`. |
| The body, `bh=`, `l=` | The approval needs nothing from the body, so the circuit neither reads nor hashes it. The signature still covers the whole signed header block, including the `DKIM-Signature` field. |
| `t=`, `x=` | Not every launch provider sets `t=`. Freshness comes from the statement's `valid_until_ledger` and its single-use attempt id (§3.1). |

### 4.5 The `From` grammar

The value of the single signed `from` field (after relaxed canonicalization,
so without leading or trailing whitespace, and with every run of whitespace
one SP) must have one of two forms:

```text
from-value    = addr-spec
              / display-name "<" addr-spec ">"     ; ">" is the last byte
display-name  = *( atext / "." / SP / quoted-string )
quoted-string = DQUOTE *( qtext / SP / quoted-pair ) DQUOTE
qtext         = %x21 / %x23-3B / %x3D / %x3F-5B / %x5D-7E   ; printable except SP " < > \
quoted-pair   = "\" ( %x20-3B / %x3D / %x3F-7E )            ; printable except < >
atext         = ALPHA / DIGIT / "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+"
              / "-" / "/" / "=" / "?" / "^" / "_" / "`" / "{" / "|" / "}" / "~"
addr-spec     = local-part "@" domain
local-part    = atom *( "." atom )                 ; RFC 5322 dot-atom, no quoting
atom          = 1*atext
domain        = label 1*( "." label )              ; at least two labels
label         = let-dig [ *61( let-dig / "-" ) let-dig ]   ; RFC 1123 §2.1, 1 to 63 bytes
let-dig       = ALPHA / DIGIT
```

- The display name is RFC 5322's `phrase` without comments or folding:
  words of `atext`, quoted strings, and `.`, separated by SP or adjacent.
  RFC 2047 encoded-words (`=?charset?B?...?=`, `=?charset?Q?...?=`) are
  `atext` and are allowed. Outside a quoted string it holds none of
  `( ) , : ; @ \ [ ] < >`; every quoted string is closed; `\` occurs only
  inside a quoted string, as the first byte of a quoted-pair; and no `<` or
  `>` occurs inside a quoted string, as `qtext` or in a quoted-pair.
  RFC 5322 also allows comments, folding, and `<` or `>` inside quoted
  strings; the circuit refuses them. RFC 5322 allows `.` in a phrase only
  in its obsolete syntax, after a first word (§4.1); the circuit allows it
  anywhere in the display name.
- So an RFC 5322 reader finds in the display name no address list (`,`),
  no group (`:` and `;`), no comment (`(`), no second address (`@` or `<`)
  and no unclosed quoted string, and reads the value as exactly one mailbox:
  the address the circuit binds.
- If the value contains `<`, it contains exactly one `<` and exactly one `>`,
  `>` is its last byte, and the address is the bytes between them. Otherwise
  the whole value is the address. No input has two candidate addresses, and
  the address is never taken from the display name.
- Quoted local parts, comments, groups, and address lists are refused: a
  quoted local part fails `local-part`, and a comment, a group or a list
  puts a byte the display name excludes before the address.
- `1 ≤ len(addr-spec) ≤ 124` bytes (`ADDR_MAX`).
- The address is used **exactly as these bytes**: case, dots, and `+` tags
  are preserved, and nothing is normalized.
- Labels follow RFC 1123 host-name syntax, so a label may start with a
  digit (`123mail.org`). Which domains are usable is decided by the registry
  allowlist (§7.3), not by this grammar.

Why the display name is restricted: a provider authenticates the sender of
mail it signs (A1b, §11.1), and an approval is evidence of inbox control
only when the `From` address the circuit binds (§11.2, property 1) is the
one the provider authenticated. A value such as
`attacker@yahoo.com, x <victim@yahoo.com>` is a valid address list whose
first mailbox is the attacker's, and Chen, Paxson and Jiang report servers
(Yahoo and iCloud among them) that "accept multiple addresses and only check
the first address" ("Composition Kills", USENIX Security 2020, §6.2,
<https://www.usenix.org/system/files/sec20-chen-jianjun.pdf>). With this
grammar the circuit accepts a value only when an RFC 5322 reader reads the
bound address as its one mailbox, so A1b needs the provider to authenticate
that mailbox and not the first address of a list.

The circuit's `From` parser implements this grammar **[built, tested]**
(`circuits/email-recovery/lib/src/from_address.nr`, with the display-name
automaton in `header.nr` and `tables.nr`; tests in
`circuits/email-recovery/tests/`, the display name in
`display_name_tests.nr`; its reading of real and fuzzed headers against
RFC 5322 readers in `research/email-recovery/eval/parser/`, §12).

### 4.6 Getting the email to the browser

The signed octets must reach the browser that proves them. Two paths, the
same for the recovery email and the enrollment email (§5.4):

**Sealed inbound (default).** `RECOVERY_INBOX`'s MX runs inside the alert
vault's enclave (§10.5), so the message is readable there and nowhere else:

1. Before showing the email to send, the browser draws a 32-octet seed and a
   16-octet inbox id `i`, derives a device key pair from the seed (RFC 9180
   `DeriveKeyPair`, the vault's HPKE suite), verifies the vault's
   attestation (§10.5), and posts
   `HPKE-seal(vault key, info = "nido/email-recovery/v1/inbound-request",
   CBOR{v: 1, value, id: i, device_key})` to the host (`POST /v1/inbound`).
   `value` is the 32 octets whose hex ends the Subject: `T` for a recovery
   email (§4.2), `E` for an enrollment email (§5.4). The seed and `i` stay in
   the browser.
2. The vault keeps the registration in enclave memory for 24 hours. The
   first registration of a value holds it: a later one for the same value is
   refused, so whoever learns `T` from the Subject (the mail provider) after
   the browser registered cannot have the message sealed to another key.
   The recovery page shows when the registration ends and, once it has,
   offers a new email (a new `rho`, so a new `T`, and a new registration)
   (`inboundDeadline`, `emailStep.ts`) **[built, tested]**.
3. When mail for `RECOVERY_INBOX` arrives, the vault reads every `Subject`
   field that ends with either phrase and a 64-character value. For each
   registered value it seals the raw message (the octets the MX received,
   trace fields included) to that registration's device key
   (`info = "nido/email-recovery/v1/inbound-message"`, associated data `i`),
   at most four messages per registration, hands the sealed copies to the
   host, and keeps nothing. The circuit, not this routing, decides which
   `Subject` is signed (§4.3).
4. The host stores the sealed copies under `i` for 24 hours and serves them
   (`GET /v1/inbound/<i>`); the browser opens them with its device key.

The host sees `i`, sizes and times, never `T`, `E`, the address or the
message. The vault holds at most `INBOUND_MAX_REGISTRATIONS` = 100,000
registrations; so that a flood cannot fill them, the host accepts at most 10
registrations per client per hour (`INBOUND_LIMIT`; a client is an IPv4
address or an IPv6 /64 prefix) and answers `429` with `Retry-After` beyond
that. One client then holds at most 240 registrations at once, and filling
the vault takes at least 417 distinct clients **[built, tested]**
(`infra/email-alerts/src/service.ts`; `test/inbound.test.ts`, "the
sealed-inbound rate limit"). A flood from more clients than that still
fills it; the `.eml` import is unaffected. In a deployment, SMTP's TLS terminates inside the enclave (not
built, as for the alert vault's own channel, §10.5); a sending MTA that does
not use STARTTLS would expose the message to the host, which MTA-STS on the
recovery domain makes a sender refuse. **[built, tested]**: the browser half
is `packages/email-recovery/src/inbound.ts`, the vault half
`infra/email-alerts/src/vault/inbound.ts` with the host routes in
`src/service.ts`; `infra/email-alerts/test/inbound.test.ts` seals a Gmail
mock's recovery email to the registering browser and to no one else,
refuses a second registration of the same value, a message for an
unregistered value, and envelopes not sealed to the vault, and shows the
host's state never holds the address. The enclave, its MX and the TLS
termination are TEST-ONLY mocks here.

**`.eml` import.** The user downloads the sent message from their Sent
folder and the browser reads the file. Nobody new sees the message. Whether
every launch provider's Sent copy keeps its `DKIM-Signature` is open
(§13 question 6).

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
`C` disables only that owner's email factor.

The check applies the recovery circuit's own rules to the enrollment email
(§4.3 rules 2 to 7, the §4.5 grammar, `HEADER_MAX`), so an inbox whose
recovery email could never be proven is refused at enrollment rather than
discovered at recovery **[built, tested]**
(`checkEnrollmentEmail` in `packages/email-recovery/src/enrollmentEmail.ts`;
`test/enrollmentEmail.test.ts`: an honest Gmail enrollment email is
accepted and `C` is its signed address's commitment; another account,
another `rho_e`, the recovery phrase, a key that did not sign it, and a
domain outside the allowlist are refused; the grammar cases of §4.5).

**The wallet's enrollment flow** (`/security/recovery/email/`,
`packages/frontend/src/lib/recovery/emailEnrollPage.ts`), while the owner
holds the account's passkey **[built, tested]**:

1. Draw `account_code` (§5.1) and save a backup (§5.6). Saving is shown,
   not ticked: once the user says the code is saved, the code leaves the
   screen and the user types back two groups of it, picked at random, from
   wherever it was saved, before enrollment continues (`kitCheckGroups`,
   `kitCheckMatches`; `emailBackup.ts`, `emailBackup.test.ts`). On an
   iPhone or iPad, *Print the kit* comes first and the page says that a
   download goes to iCloud Drive unless Safari's download location was
   changed (`kitActions`).
2. Show the enrollment email (a `mailto:` link and the exact To and
   Subject), receive it back (§4.6), and check it as above, with the key from
   the key list or, after a notice, DNS (§7.7).
3. Register the alert contact with its Web Push subscription and confirm it
   with the emailed code (§10.3); the wallet's service worker
   (`packages/frontend/public/sw.js`) shows the pushes. The alert address
   field starts empty. If the user enters the enrolled inbox itself, the
   page warns, without blocking, that someone who takes over that inbox can
   delete the alerts sent to it, and recommends an address at another
   provider (`alertAddressWarning`). When the inbox's provider is the
   platform that likely syncs this device's passkey (`gmail.com` or
   `googlemail.com` in Chrome or on Android, `icloud.com`, `me.com` or
   `mac.com` on Apple platforms, read from the user agent), the page notes
   that losing that one account would lose the passkey and the inbox
   together, and recommends another inbox or another helper
   (`syncedPasskeyNote`). The page names what each party sees: the mail
   provider sees that a Nido recovery email was sent and when, and a chain
   watcher may link it to the account by timing (`PROVIDER_SEES`); the
   address is stored only in the vault and only when alerts go to it, and
   the sending services that deliver alerts, named, see it then
   (`ENROLLED_ADDRESS_NOTE`, `CONSENT_TEXT` version 3; §10.7).
4. Deploy the guardian with `C` and the pin (§7.4), paid by the wallet's
   submitter account (§13 question 10), then read back its wasm hash and
   `config()` and compare every field with what it intended (§5.5).
5. Apply a document whose recovery member lists the guardian as
   `{ kind: 'email', ... }` with `secondAlertChannel: 'web-push'`, through
   `recoverySpec` (§9.3), under `Protected` after collecting the current
   condition.

Progress lives in the tab's `sessionStorage`, so leaving for the mail app
keeps it; `account_code` is there until enrollment ends and is sent nowhere.
The end-to-end test (§12) drives every step.

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
v2.<base64url-no-padding( salt || nonce || ciphertext )>
-----END NIDO RECOVERY CODE-----

key        = Argon2id(password = passphrase, salt, t = 3, m = 65536 KiB, p = 4, tag = 32 bytes)
ciphertext = AES-256-GCM(key, nonce, plaintext = account_code || account contract id,
                         aad = "nido/email-recovery/v1/code-backup-v2")
```

The account rides inside the ciphertext: once the passphrase opens the
block, it says which Nido it recovers (§5.7), and the mail provider that
keeps the Sent copy learns nothing from it. Wallets write version 2 and
still open version 1 blocks, which carry the code alone with the account as
associated data (`aad = "nido/email-recovery/v1/code-backup" || account
contract id`) and so open only given the account.

- `salt` is 16 random bytes and `nonce` 12 random bytes. The Argon2id
  parameters are RFC 9106 §4's second recommended option (64 MiB, 3 passes,
  4 lanes, 128-bit salt, 256-bit tag), sized for phone browsers.
- `ciphertext` is the 48 bytes of code and account plus the 16-byte tag, so
  the encoded payload is 92 bytes (123 base64url characters); a version 1
  payload is 60 bytes (80 characters), so the two cannot be confused.
- **Passphrase floor:** the wallet generates the passphrase; it is not
  user-chosen. It is five words drawn uniformly from the EFF large wordlist
  (7,776 words), lowercase, separated by single spaces, at least 64.6 bits.
  The Argon2id password is its UTF-8 bytes.
- The provider stores the ciphertext. Without the passphrase it cannot
  recover `account_code`, so it cannot compute `C` and link the inbox to the
  guardian.

**(b) Recovery kit / password manager:** the 16 bytes as 26 characters of
RFC 4648 base32 without padding, shown in groups of four. The kit file also
names the Nido it recovers (its `C…` address), the address of its recovery
page (§5.7) and Nido's apex (`nido.fyi` on mainnet, `test.nido.fyi` on
testnet: a constant of the build, never read from the page's own address),
and the page advises keeping it outside the account behind the enrolled
inbox (not in that provider's password manager or cloud drive), since
whoever takes over that account would hold both the inbox and the code
(`recoveryKitText`, `KIT_STORAGE_ADVICE`, `walletApex`).

**[built, tested]**: `packages/email-recovery/src/backup.ts` (the Argon2id
of `@noble/hashes`, checked against RFC 9106 §5.3's test vector; the EFF
large wordlist with its published SHA-256 in `src/effWordlist.ts`);
`test/enrollmentEmail.test.ts` opens a block only with its passphrase
(case and spacing forgiven) and account, finds it inside a whole email
body, reads the account out of a version 2 block, still opens a version 1
block with its account and only with it, and round-trips and refuses
mistyped kit codes. Which backups a
wallet offers is open (§13 question 4); the wallet offers both from one
component (`packages/frontend/src/lib/recovery/emailBackup.ts`), so the
choice changes there alone. At recovery the user enters the kit code, or the
block and its passphrase.

**Checking the code before it is needed** **[built, tested]**. Recovery
settings offer *Check my recovery code*: the user types the kit code and the
wallet, storing and sending nothing, recomputes the guardian's pin root from
it (leaf 0 is `P2(DOM_PIN_SALT, account_code)`, §7.4) with each key of the
key list (§7.7) as leaf 1, and compares the result with the pin root in the
guardian's `config()`. A match means the code is the guardian's. No match
means either a wrong code or an enrollment key the key list does not hold;
the page tells the user to look for another copy and, failing that, to
enroll again while the passkey still works (`checkCodeAgainstPin`,
`codeCheckText` in `emailModel.ts`; `settingsPage.ts`).

### 5.7 Finding the account after losing every device

A Nido's recovery page runs on the account's own subdomain, whose name is
the 56-character `C…` address. The recovery kit names that address and the
recovery page (§5.6 (b)); the version 2 backup block carries the address
inside its ciphertext. Opened anywhere else (the wallet's apex), the
recovery page asks for the address from the kit, the recovery page's
address, or the Nido's registered name, and goes to the account's recovery
page (`accountFromKitInput`; `recoverPage.ts`) **[built, tested]**. Nothing
names the account in plaintext where the mail provider keeps it.

Where the recovery code is typed, the page says that nobody from Nido asks
for it, and to check that the address bar shows exactly the recovery page
the kit names, built from the build's apex constant, and that every Nido
page ends in that apex (`codeEntryWarning`) **[built, tested]**. This helps
an honest user tell a lookalike page from the real one; a user talked into
sending the email by an attacker who runs the real recovery page on the
attacker's own device sees neither this warning nor the prepared email
(§11.4).

## 6. Circuit public inputs and obligations

### 6.1 Public inputs

The circuit has exactly four public inputs, BN254 field elements in this
order. The guardian hands them to the verifier as one 128-byte blob, each
input 32 bytes big-endian (`PUBLIC_INPUTS_LEN = 128`). The circuit
(`circuits/email-recovery/recovery`) declares exactly these, in this order
**[built, tested]**:

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

Private inputs: the signed header bytes `H` and their length (at most
`HEADER_MAX` = 1536 bytes, §6.3), the signature `s`, the modulus `n`
(§7.1) with noir-bignum's Barrett parameter (read only by unconstrained
code, so it is a prover hint, not part of the key hash), `rho`,
`account_code`, the leaf index, and the 16 Merkle siblings. The positions
of the `From` address, the Subject value, and the DKIM-Signature tags within
`H` are prover hints the circuit computes in unconstrained code and then
checks. The leaf domain is not a separate input: it is the lowercase `d=`
value the circuit reads from `H`, so C4's second equality holds by
construction.

| Id | Obligation |
| --- | --- |
| C1 | `s < n`, `n` has exactly 2048 bits, and `s^65537 mod n` equals the EMSA-PKCS1-v1_5 encoding of `SHA-256(H)`. |
| C2 | `H` is a well-formed signed header block under §4.3 rules 3 to 6: header fields in relaxed canonical form, each ended by CRLF, then the `dkim-signature` field with an empty `b=` and no trailing CRLF (RFC 6376 §3.7), carrying `v=1`, `a=rsa-sha256`, relaxed header canonicalization, an `h=` that names `from` and `subject`, and a `d=` value. The circuit does not hash any byte outside `H` and zeroes every input byte past `len(H)`. |
| C3 | `H` contains exactly one `from` field; its value parses under §4.5 to `addr-spec`; `P2(DOM_COMMIT, len, pack(addr-spec, 124), account_code) = C`. |
| C4 | `lowercase(domain(addr-spec)) = lowercase(d=) = leaf domain`. |
| C5 | `H` contains exactly one `subject` field, its value is exactly `APPROVE NIDO ACCOUNT RECOVERY ` followed by 64 lowercase hexadecimal characters, and those characters are `hex(P2(DOM_BLIND, digest_hi, digest_lo, rho))`. |
| C6 | `key_hash = P2(DOM_KEY, limbs(n))` (§7.1), `leaf = P2(DOM_LEAF, len(domain), pack(domain, 62), key_hash)` (§7.2), and the Merkle path from `leaf` at the given index reaches `key_root` (§7.2). |

**[built, tested]**: `circuits/email-recovery/lib/src/recovery.nr`
(`verify_recovery_email`, composing the components of
`circuits/email-recovery/lib`), compiled to 248,996 UltraHonk gates
(padded to 2^18) with Perch's pinned nargo 1.0.0-beta.9 and proven with bb
0.87.0 in the zero-knowledge flavor with the keccak transcript, which
Perch's verifier accepts. The tests:

| Tests | What they show |
| --- | --- |
| `circuits/email-recovery/tests/src/recovery_tests.nr` (19) | The honest witness at any leaf index is accepted; a commitment to another address, to a case variant of it, or under another code, another digest limb, swapped limbs, another `rho`, a root without the key, the key under another domain, another key for the domain, a wrong or 16-bit-overflowing leaf index, the leaf as root, and a signature under another key are each refused at their obligation |
| the rest of `circuits/email-recovery/tests/` (124) | Each component, one negative test per publicly documented soundness issue class of open-source email circuits (`circuits/email-recovery/SECURITY.md`), and the display-name grammar of §4.5 (`display_name_tests.nr`: address lists, a second mailbox, an unclosed quoted string, each special outside a quoted string; quoted, encoded-word and bare forms accepted) |
| `packages/email-recovery/test/recoveryInputs.test.ts` | The committed circuit (`circuits/email-recovery/artifacts/recovery.json`, run with noir_js) accepts an honest recovery email from each domain the provider mocks sign for, and a 124-byte address with a 500-byte display name at each launch domain; the encoder's signed header block equals the octets every mock provider's key signed |
| `packages/email-recovery/test/attacks.test.ts` (60 cases) | Every adversarial email of `packages/email-mocks` with the strongest witness for its claim: each case a standard DKIM verifier passes but whose claim must not be provable is refused at a named assertion (§6.4) |
| `crates/integration-tests/tests/it/email_proofs.rs` | A real proof of each launch domain's recovery email verifies on chain and counts as one vote (§8.6) |

### 6.3 Header bound

`HEADER_MAX` = 1536 bytes. Measured on the provider mocks' formats
(`circuits/email-recovery/README.md`, "Header bound"), every launch
domain's recovery email fits, and with the longest address (124 bytes) it
still fits with a display name of up to 536 bytes (WEB.DE), 539 and 540
(GMX), 779 to 797 (Proton, Fastmail, Gmail), 842 (iCloud), 886 (Outlook.com
and Hotmail), and 965 (Yahoo). GMX and WEB.DE sign the address twice, which
is why a 1024-byte bound would have left them only 24 to 28 bytes for a
display name at that length. The circuit at 1536 bytes stays at 2^18, the
padded size it has at 1024 bytes, so the bound changes neither the
verification key's size nor the on-chain verification cost
(`circuits/email-recovery/MEASUREMENTS.md`) **[measured]**. The
DKIM-Signature field is bounded at 512 bytes and 16 tags; the largest launch
format uses 355 bytes and 11 tags.

### 6.4 Attack suite

`packages/email-recovery/test/attacks.test.ts` gives every adversarial
email of `packages/email-mocks` (`buildAttacks`, with this Subject format)
the witness most favourable to its claim: a signature a standard verifier
accepts under the key DNS publishes for its `d=` and selector; the octets
that signature covers; the registry tree of the launch keys, or, for a key
no registry would hold, a tree planted with that key; and the public inputs
the claimed account's guardian would build. It pins each outcome
**[built, tested]**:

- every case a standard DKIM verifier passes but whose claim must not be
  provable is refused: display-name, angle-addr, comment, quoted-local-part
  and folded `From` spoofing; `From` values an RFC 5322 reader reads as an
  address list, as another mailbox, or as no mailbox (§4.5); unsigned `From`
  or `Subject` fields above or below the signed one; a second, invalid
  signature under the claimed `d=` above a valid one by another domain;
  misaligned `d=`; an RSA-1024 key; `l=` with appended text; encoded-word,
  folded-value and split-phrase Subjects; the recovery value in the display
  name or body; and replay for another statement or account;
- every case no signature of verifies is refused too, except a body
  replaced after signing: the header signature is the provider's own and the
  proof does not bind the body (§4.4);
- a Subject folded at a space, or with runs of whitespace, is accepted,
  because relaxed canonicalization restores the exact phrase.

The evaluation runs the same adversarial emails against live attempts on a
local Stellar network, with the attacker's strongest witness for each
account's real commitment, statement and accepted key tree, and gets the
same outcome for every case; it also proves and submits the forged emails
that still yield a witness (a key no accepted tree holds, a guessed account
code) and takes each attack class past the circuit to the chain
(`research/email-recovery/eval/README.md`, §12) **[built, tested]**.

### 6.5 The browser prover

The proof is made in the user's browser by `RecoveryProver`
(`packages/email-recovery/src/prover/`), with noir_js 1.0.0-beta.9 for the
witness and Barretenberg 0.87.0 (bb.js) for the zero-knowledge UltraHonk
proof in the keccak flavor (§6.2) **[built, tested]**:

- **A Web Worker per proof.** The page posts one request (the email and the
  witness inputs of `encodeRecoveryEmail`); the worker answers with progress
  events in stage order (`download`, `witness`, `proving`, `verifying`, each
  with the elapsed time, and octets loaded during `download`) and one `done`
  or `error` naming the stage and whether the input, an asset, the prover or
  the verification failed. The worker is terminated afterwards, which hands
  Barretenberg's memory back to the browser.
- **Threads.** Barretenberg runs on `navigator.hardwareConcurrency` threads
  (at most 32) when the page is cross-origin isolated, on one thread
  otherwise. The recovery routes are cross-origin isolated (below).
- **What it downloads, once.** The circuit artifact (1,885,167 octets), its
  verification key (1,760), and the prefix of Barretenberg's BN254 CRS the
  2^18 circuit needs (262,145 G1 points, 16,777,280 octets, and the
  128-octet G2 point): 18,664,335 octets, kept in the Cache API so a retry
  reads them locally. The CRS comes from Barretenberg's host
  (`crs.aztec.network`) and is checked against SHA-256 digests pinned in the
  prover (`CRS_G1_SHA256`, `CRS_G2_SHA256`) before it is used or stored; the
  verification key must hash to the circuit id. The prover's code (the
  worker, bb.js with its wasm, noir_js with its wasm) is part of the page's
  build: with the page, 8,393,672 octets uncompressed, so a first proof
  transfers 27,192,989 octets in all, the page's fonts included (§12).
- **Local verification.** Before a proof is returned, its public inputs
  must be the four the guardian will build (§6.1), and it must verify under
  the verification key whose SHA-256 is the circuit id the guardian's
  verifier reports (§8.4): the committed key, which equals the key bb.js
  computes from the artifact.

`packages/email-recovery/test/prover.test.ts` pins the request and event
checks, the thread rule, stage order and timing, the cache (a retry
downloads nothing; a corrupted entry or a wrong digest is refused; a range
request answered in full is cut; a short body is refused), each error code
at its stage, the client and worker over a `MessageChannel`, and one real
proof of the Gmail fixture through the same code, which bb.js's own verifier
accepts and refuses with one byte changed.

**Recovery routes' headers.** `/security/recover*` and `/security/recovery*`
are served with `Cross-Origin-Opener-Policy: same-origin` and
`Cross-Origin-Embedder-Policy: require-corp`, and the build's assets
(`/_astro/*`, which include the worker scripts) with COEP, because an
isolated page may only start a worker whose script sends it. `require-corp`
suffices: everything those pages load is same-origin, or answers CORS
(`crs.aztec.network`, the Stellar RPC, the alert service), or sends
`Cross-Origin-Resource-Policy: cross-origin` (Google Fonts). The guardian
approval page is not isolated, because a classic Stellar wallet signs there
through a popup that same-origin COOP would cut off. Both places the
frontend sets headers (`packages/frontend/public/_headers` and
`frontend/worker-proxy-nido/index.js`) carry the rules, and
`tests/support/headers.test.ts` checks they agree. The wallet's iframe to
the apex's storage bridge is already refused on every page by
`X-Frame-Options: DENY`, isolated or not. The report-only CSP lists what the
provers need once it is enforced: `'wasm-unsafe-eval'`, `data:` (bb.js reads
its wasm from a `data:` URL), `crs.aztec.network`, and the DNS-over-HTTPS
resolver of §7.7.

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
`is_accepted_root(root) -> bool`, at the current ledger's close time
(`DkimRegistryInterface`, `contracts/email-guardian/src/registry.rs`). The
registry contract (`contracts/dkim-registry`, §7.6) answers it from its own
state as follows **[built, tested]**:

1. **Activation.** A root that adds a key becomes acceptable only when that
   addition executes, and an addition executes only after its timelock:
   `TIMELOCK_ATTESTED_SECONDS = 259,200` (72 hours) of ledger close time
   after the later of its approval and the moment since which at least
   `attest_threshold` attesters' latest observations see the key live in
   DNS (`attested_at`, §7.5), or `TIMELOCK_SECONDS = 604,800` (7 days) after
   its approval, whichever comes first. Each moment is the close time of the
   ledger the event happened in, and the addition executes in the first
   ledger whose close time is at or past the deadline. Additions are
   proposed and approved by the registry's multisig. The 72-hour path is
   closed to a key that was ever revoked (rule 3).
2. **Grace.** A root superseded in a ledger with close time `S` stays
   acceptable while the close time is at most `S + grace_seconds`, so a
   proof generated against the previous root still verifies and a key the
   provider has just retired keeps working briefly. The registry keeps at most `MAX_LIVE_ROOTS = 16` roots (the
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
pin = { root, valid_until }    // valid_until: a ledger close time, Unix seconds
```

- **Additive.** The guardian accepts `key_root` if it is the pin root and
  the current ledger's close time is at most `valid_until`, or if the registry
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
  whose `valid_until` is more than `MAX_PIN_LIFETIME_SECONDS = 31,536,000`
  (365 days) past the deployment ledger's close time **[built, tested]**.
- **On the registry's clock.** The pin's expiry is a close time, like the
  registry's timelocks and grace, so the window it keeps a key usable for
  has the same wall-clock length whatever the network's target ledger close
  time, and the guardian compares one clock for every key-trust window. The
  statement's expiry, which check 9 compares, stays Perch's ledger number
  (§3.1). The circuit and the proof do not depend on the pin's expiry.
- **The revocation bound.** The pin is the one path the registry cannot
  close. If the registry revokes a pinned key for compromise at close time
  `T_r`, a guardian whose pin tree holds that key still accepts it through
  the pin until its `valid_until`, at most 365 days after the guardian was
  deployed, whatever `T_r` is. During that window, forging
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
`observed_live = 0`. The proposal's `attested_at` is the close time of the
ledger since which the counted observations have numbered at least
`attest_threshold`; a newer observation that drops the count below the
threshold clears it, and reaching the threshold again sets it to that
ledger's close time. Every observation is published
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

**Clock.** Every duration the registry keeps is in seconds of ledger close
time (`env.ledger().timestamp()`), never a count of ledgers: the two
timelocks, the grace period, the proposal lifetime, and the attestation age
and skew (§7.5). Validators set the close time by consensus; stellar-core
accepts a ledger only if its close time is later than the previous ledger's
and at most 60 seconds past the validating node's own clock
(`HerderSCPDriver::checkCloseTime`, `MAX_TIME_SLIP_SECONDS`). A timelock
therefore lasts its wall-clock length whatever the network's target ledger
close time, which validators can change by vote (§11.1 A9), and a quorum of
validators with honest clocks cannot end it more than a minute early. The
registry is immutable, so a duration stated in ledgers would be fixed for
its lifetime.

**Construction.** `__constructor(config: RegistryConfig)` refuses
(`DkimRegistryError`) unless:

| Field | Check | Error |
| --- | --- | --- |
| `members: Vec<Address>` | 1 to `MAX_MEMBERS = 20`, distinct | `InvalidMembers` (1) |
| `threshold`, `revoke_threshold` | `1 ≤ revoke_threshold ≤ threshold ≤ members` | `InvalidThreshold` (2) |
| `attesters: Vec<BytesN<32>>` (Ed25519 keys) | 1 to `MAX_ATTESTERS = 20`, distinct | `InvalidAttesters` (3) |
| `attest_threshold` | `1 ≤ attest_threshold ≤ attesters` | `InvalidAttestThreshold` (4) |
| `grace_seconds: u64` | at most `MAX_GRACE_SECONDS = 604,800` (7 days) | `InvalidGrace` (5) |
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

A proposal lapses `PROPOSAL_LIFETIME_SECONDS = 2,592,000` (30 days) of
ledger close time after it was created: it can no longer be approved, attested, or executed
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
| `proposal(id)`, `eligible_at(id)` | a proposal with its approvals, attestations, and execution; an approved addition's earliest eligible close time (Unix seconds) |
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
| `key_retired` | domain; id, key hash, index, new root, previous root, the last close time the previous root is accepted at |
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
| `grace_seconds` | 86,400 (24 hours) | Covers phone proving (up to about two minutes), mail delivery, and a proof made the same day against the previous root. Open (§13 item 5). |
| `domains` | `nido_dkim_registry::LAUNCH_DOMAINS`: `gmail.com`, `outlook.com`, `hotmail.com`, `icloud.com`, `yahoo.com`, `proton.me`, `protonmail.com`, `fastmail.com`, `gmx.net`, `gmx.de`, `web.de` | The launch providers' primary address domains. Each must also be the `d=` its provider signs with (§4.3 rule 7); open per provider (§13 item 6). |

**Tests [built, tested].** `contracts/dkim-registry/src/test.rs` covers
every construction refusal; allowlist and key-size refusals; the key hash
being computed, never supplied (`the_key_hash_is_computed_never_supplied`);
k-of-n approval and member authorization; both timelocks one second before
and at their boundary
(`an_attested_addition_activates_after_exactly_72_hours`,
`any_other_addition_activates_after_exactly_7_days`) and where the 72-hour
clock starts; grace expiry one second past its end; the timelocks and grace holding in
seconds when four times as many ledgers close in them
(`timelocks_and_grace_follow_close_time_not_ledger_count`); the live-root cap; retirement; revocation
refusing roots in grace, sparing roots without the key, reaching an already
retired key, stopping a pending addition, and the 7-day-only return; every
attestation refusal and malformed encoding; an attester's latest
observation replacing its earlier one and stopping or restarting the
72-hour clock (`an_attesters_latest_observation_counts`); and every event. The
integration tests run the registry from its wasm, fed by the mock:

| Test | What it shows |
| --- | --- |
| `email_guardian.rs::a_key_added_through_the_attested_path_is_refused_before_72_hours_and_accepted_after` | An approval proven against the root a pending addition will produce is refused by the guardian (`UnknownRoot`) one second before the 72 hours end, and counted from the ledger the addition executes in |
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

### 7.7 Finding the signing key: the key list, then DNS

To check an enrollment email and to prove a recovery email, the wallet needs
the RSA modulus that signed it. Asking for one key reveals the provider, so
the wallet asks for all of them first:

1. **The key list.** One static file on the wallet's origin
   (`/dkim-keys.json`), the same for every user, lists every key the registry
   knows for the launch domains: `{version: 1, network, registry, ledger,
   keys: [{domain, selectors, modulus, keyHash, status}]}`, `status`
   `active` (a leaf of the current tree) or `pending` (an approved addition
   in its timelock). The wallet recomputes each `keyHash` from its modulus
   and refuses the file if one differs (`parseKeyList`), tries the list's
   keys for the email's `d=` (those its attesters saw under the email's
   selector first) against the email's signature, and uses a key only when
   the chain confirms it: its leaf is in the guardian's pin tree with the pin
   live, or under a root the registry accepts, with the path the proof uses
   (`chooseKeyPath`). Whoever serves the file therefore cannot substitute a
   key: a key nobody registered or pinned yields no path, and at enrollment a
   substituted key does not verify the email the provider signed.
   `packages/email-recovery/scripts/dkim-key-list.mjs` writes the file from
   the registry: it reads `key_proposed` and `dns_attested` events, asks the
   registry about each key (`leaf`, `proposal`), keeps `active` and `pending`
   keys, and merges its previous output, because an RPC keeps a bounded
   history.
2. **DNS, as a fallback.** Only when the list has no key that signed the
   email (a key just rotated and not yet proposed), and only after telling
   the user that the resolver will learn which mail provider they use, the
   wallet reads `<selector>._domainkey.<domain>` through a configurable
   DNS-over-HTTPS resolver's JSON API (`application/dns-json`, the format
   Cloudflare and Google publish) and parses the key record (RFC 6376
   §3.6.1: `p=` as `RSAPublicKey` or `SubjectPublicKeyInfo`, an empty `p=`
   revoked, RSA-2048 with exponent 65537 only). At enrollment such a key is
   what the pin holds; at recovery it is still used only through the pin or
   the registry.

No lookup goes through Nido's hosts. **[built, tested]**:
`packages/email-recovery/src/dkimKey.ts` (`test/dkimKey.test.ts`: every
launch key the provider mocks' DNS publishes, read back through the DoH JSON
format of `@nidohq/email-mocks`'s `dohJson`, verifies its provider's mail;
both DER forms read the same; revoked, non-RSA, short, duplicated and
malformed records are refused; CNAME hops are skipped; a list whose hash
does not match its modulus is refused), `packages/frontend/src/lib/recovery/emailRecovery.ts`
(the chain checks), and the end-to-end test (§12), where the list holds the
Gmail mock's key while its addition waits in the timelock and the pin
carries it.

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
struct KeyPin { root: BytesN<32>, valid_until: u64 }   // a ledger close time, Unix seconds

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
| at most one pin; its root below `r`; deployment close time `≤ valid_until ≤` deployment close time + 31,536,000 | `InvalidPin` (5) |
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
| 11 | `key_root` equals the pin root with the current ledger's close time `≤` the pin's `valid_until`; otherwise `registry.is_accepted_root(key_root)` returns `true` | `UnknownRoot` (20), or `RegistryUnavailable` (21) if the call fails |
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
`contracts/email-guardian/src/verifier.rs`).

That contract is `contracts/email-verifier` (crate `nido-email-verifier`)
**[built, tested]**: it embeds `UltraHonkZkVerifier` from the same Perch
commit as the other Perch crates and the circuit's 1,760-byte key
(`contracts/email-verifier/vk/email_recovery.vk`, `bb write_vk --scheme
ultra_honk --oracle_hash keccak`), exposes `verify_proof`, `circuit_id`,
`vk` and `version`, refuses a proof that is not 16,224 bytes or public
inputs that are not 128 bytes (`ProofParseError`), and links a 128 KiB wasm
stack, as Perch's adapter does. Its tests (`src/test.rs`) verify every
committed proof, including one made by bb.js, and refuse each public input
changed, a non-canonical input, changed proof bytes, a real proof of
Perch's own circuit, and wrong lengths.

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
integration tests (§7.6, §8.6, §9.3) use the real verifier and the registry
contract from their wasm, and every approval in them carries a real proof.

### 8.6 Real proofs on chain

`crates/integration-tests/src/email_proof.rs` gives every integration test
approval a real proof: the provider mock signs the recovery email for the
statement the real controller built, `packages/email-recovery` encodes it,
Perch's pinned bb proves it, and the proof is committed with its email
(`crates/integration-tests/fixtures/email/<name>/`); a test whose statement,
inbox, key path or circuit drifts fails with the command that regenerates
them (`just gen-email-proofs`). The registry admits each launch domain's
TEST-ONLY key through the attested path, fed by the DNS attester mock with
the mock DNS's records (`fixtures/email/keys.json`) **[built, tested]**:

| Test | What it shows |
| --- | --- |
| `email_proofs.rs::<domain>_approval_counts_one_vote` (11) | For each launch domain: the verifier accepts the proof for the guardian's public inputs and refuses it with each one changed; `submit_guardian` carrying it counts one vote; the resources of §12 |
| `email_proofs.rs::long_address_at_web_de_counts_one_vote` | The same for a 124-byte address with a 299-byte display name at WEB.DE |
| `email_proofs.rs::the_fixture_keys_and_hashing_match_the_circuit` | The provider keys cover the registry's allowlist, and the harness's native `C` is the circuit's and the encoder's (one vector pinned in all three) |
| `contracts/email-verifier/src/test.rs` | As §8.4 |

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
   passkey device, §10). The rule holds at runtime, not only at enrollment:
   the recovery settings page checks the channel (this device's own
   subscription and its last acknowledged probe at once; the vault's view
   of every device, `status` of §10.3, with the passkey) and, while no
   device is live (each one lapsed, the push service having answered 404 or
   410, or unacknowledged, having confirmed none of two probes, §10.6; or
   this device's subscription is gone), shows it prominently, offers to add
   this device (`push` of §10.3, at once), and refuses to save a
   configuration that keeps the email guardian until a device is live.
3. **Email plus delay.** If the email vote alone authorizes an attempt
   (`guardian-only` mode with `quorum = 1`), the member must use the `loss`
   profile and a delay of at least 7 days of ledgers at the network's target
   ledger close time: `delay-ledgers ≥ ⌈604,800,000 / t⌉`, where `t` is
   `scp_timing.ledger_target_close_time_milliseconds` (CAP-0070), which the
   wallet reads through Stellar RPC `getLedgerEntries` (`ledgerTargetCloseMs`
   in `packages/passkey-sdk/src/perch/ledgerTiming.ts`) when it builds the
   member, and passes as `RecoveryChoice.ledgerCloseMs`. At the 5,000 ms
   testnet and mainnet set (read from both networks), the floor is 120,960
   ledgers; at 4,000 ms, the lowest target protocol 23 allows, it is
   151,200. Without `t`, or with a `t` that is not a positive integer, the
   builder refuses the member. The delay itself is Perch's ledger count, so
   a target lowered after the member was built shortens it in wall-clock
   time until the owner rebuilds the member (§11.1 A9). In `combined` mode
   the ZK factor is always needed as well, so this case does not arise
   there.
4. **Allowed actions.** The guardian is deployed with `ALLOW_ALL`. A
   narrower set is refused whenever the email vote is needed to reach the
   quorum (the member's other guardians number fewer than `quorum`),
   because a `Protected` account whose quorum needs the email vote could
   otherwise never reconfigure or upgrade.

The builder tells the email guardian apart by a typed marker, never by its
address: the wallet lists it in `RecoveryChoice.guardians` as
`{ kind: 'email', address, allowedActions }` when it deploys it, and states
the registered second channel as `RecoveryChoice.secondAlertChannel`
(`'web-push'`). The alert service registers the channel and refuses an
email-guardian contact without it (§10.3) **[built, tested]**.
`packages/passkey-sdk/src/perch/recoverySpec.test.ts`
("email guardian rules") pins each rule at its boundary **[built, tested]**:

| Test | What it shows |
| --- | --- |
| `rule 1: accepts one email guardian and refuses a second` | One email guardian is accepted; two are refused |
| `rule 2: an email guardian needs a second alert channel` | With `secondAlertChannel` accepted, without it refused |
| `rule 3: email alone needs the loss profile and a delay of at least 7 days of ledgers at the network close time` | `guardian-only`, quorum 1, 5,000 ms ledgers: delay 120,959 refused, 120,960 and the default accepted, `protected` refused; also with other guardians listed at quorum 1. At 4,000 ms: the default refused, 151,199 refused, 151,200 accepted. At 4,096 ms the floor rounds up (147,656 refused, 147,657 accepted). No close time, or 0, negative, fractional, or `NaN`, refused |
| `rule 3: does not apply when the email vote alone cannot authorize` | Quorum 2, and `combined` with quorum 1, accept `protected` and a 24-ledger delay |
| `rule 4: refuses narrower allowed actions when the quorum needs the email vote` | A narrower set is refused with two other guardians at quorum 3 and in `combined` with quorum 1, accepted with two other guardians at quorum 2; `ALLOW_ALL` is accepted at quorum 3 |
| `leaves configurations without an email guardian unaffected` | Without an email guardian, quorum 1, `protected`, a 24-ledger delay, and no second channel are accepted |
| `ledgerTiming.test.ts` | `ledgerTargetCloseMs` asks for exactly the SCP timing setting (ledger key `AAAACAAAABA=`, the key testnet and mainnet RPC return for it) and refuses a network without it; `emailOnlyMinDelayLedgers` is 120,960 at 5,000 ms and rounds up so the count never lasts less than 7 days |

Every save on the recovery settings page lists the account's email guardian
(found by its wasm hash, as at recovery) with its typed marker, so these
rules apply to later changes as well as to enrollment; the channel's
runtime state decides `secondAlertChannel` (`channelView` in
`emailModel.ts`, tested in `emailModel.test.ts`, "the second alert channel
at runtime (rule 2)"; `settingsEmail.test.ts` shows a lapsed channel and an
unacknowledged one refusing a save that keeps the email helper, and a save
keeping it under the rules otherwise) **[built, tested]**.

**What each layer guarantees.** On chain, for every configuration: email
approvals alone never complete a recovery without the delay passing, and
with `quorum ≥ 2` (or in `combined` mode) they never authorize one. The
wallet rules add that Nido never produces a configuration in which the
email vote alone authorizes, except under `loss` with a delay of at least 7
days at the network's target close time when the member is built, and a
second alert channel. The chain accepts any configuration the owner applies, so a
different wallet could build one Nido would refuse.

`crates/integration-tests/tests/it/email_guardian.rs` pins the on-chain part
on Nido's stack (Perch's controller and account from their deployed wasm,
the guardian, the verifier and the key registry from their wasm, the
registry fed by the DNS attester mock, and a real proof in every approval,
§8.6) **[built, tested]**:

| Test | What it shows |
| --- | --- |
| `email_approval_counts_as_exactly_one_guardian_vote` | One email approval is one vote of a 2-of-3 quorum; with one more guardian the attempt is authorized and completes only after the delay |
| `the_same_email_approval_is_not_counted_twice` | Resubmitting the approval in a fresh authorization entry is refused (`AlreadyCounted`) |
| `an_email_approval_cannot_be_replayed_into_another_attempt` | Another attempt's digest, a spliced statement and proof, and the cancel domain are all refused (`DigestMismatch`, `ProofRejected`) |
| `an_email_approval_cannot_be_replayed_into_another_account` | Even with two guardians sharing one `C`, account A's approval does not count for account B |
| `email_approvals_alone_never_complete_a_recovery` | With a 2-of-2 quorum the email vote never authorizes; as the only guardian (quorum 1, `Loss`) it authorizes, but completion waits for the delay, the owner can cancel, and a new attempt needs a new email |
| `email_approval_counts_toward_a_protected_reconfiguration` | Through `approve_change`, the email vote is one vote of a `Protected` reconfiguration quorum |
| `a_root_the_registry_does_not_accept_is_refused` | A proof's key root replaced by a root the registry never produced, or by the empty tree's, is refused (`UnknownRoot`) before the proof is checked |

## 10. Alerts

Alerts are driven by the controller's events, filtered by account, by the
network's transactions, which carry the email guardian's votes, and by
reads of the controller's state (§10.2). Nothing is written on chain for
alerts: no tag, no registration, no event from the guardian.

| Event (topic 0) | Topic 1 | Alert | Channels |
| --- | --- | --- | --- |
| `attempt_authorized` | account | **Required:** the account has entered a recovery window; generic text plus the per-attempt verification code | Every channel |
| none: the email guardian's vote on a collecting attempt (`email_vote_recorded`) | — | **Required:** the inbox and the account code were used for an attempt that still needs other approvals; found in the vote's transaction (§10.2) | Every channel |
| none: the email guardian's vote to cancel an attempt (`email_cancel_recorded`) | — | **Required:** the inbox and the account code were used to stop a recovery, perhaps the owner's own; found in the vote's transaction (§10.2) | Every channel |
| none: the email guardian's approval of a reconfiguration or upgrade (`email_change_recorded`) | — | **Required:** the inbox and the account code were used to approve a settings change; found in the approval's transaction; its code is the change digest's (§10.1) | Every channel |
| none: more than `MANY_OPEN_ATTEMPTS` (8) open attempts (`attempts_many`) | — | **Required:** many open attempts can hide the one that matters; raised by the vault when it counts `attempt_begun`, at most once per account per 24 hours (§10.2) | Every channel |
| `recovery_completed` | account | Required: the account's signers changed | Every channel |
| `epoch_advanced` | account | Required: the recovery configuration (guardians, timing, the email guardian itself) changed | Every channel |
| `attempt_cancelled` | account | Informational | Email |
| `change_evidence_recorded` | account | Informational: approvals for a reconfiguration or upgrade are being collected | Email |
| `attempt_begun` | account | None by default: opening an attempt is permissionless and grants nothing, so alerting each one would teach users to ignore recovery alerts. The vault counts the attempt among the account's open ones (`attempts_many` above), and the wallet shows open attempts itself (§10.2). A service configured with `emailOnAttemptBegun` emails it, at most one per account per 24 hours of ledger close time | None (configurable: email, rate-limited) |
| `attempt_invalidated` | account | None | None |

Each alert is delivered under an id naming what it is about
(`name:account:attempt` or `:epoch`; `alertEventId`), not the RPC event that
reported it, so the same alert found by the event stream and by
reconciliation (§10.2) is sent once. `change_evidence_recorded`, emitted for
each approval of one change, keeps its event id; `email_change_recorded` is
about the change's digest; `attempts_many` about the account and the
24-hour window it is sent in.

Topic 0 is the event struct's name in snake case, topic 1 the account, and
the data the struct's other fields as a map (`#[contractevent]` with one
`#[topic]` field; structs in `perch-recovery/src/contract.rs`) [Perch]; the
recorded events of `crates/integration-tests/tests/it/email_alerts.rs` have
exactly this shape **[built, tested]**. A completed recovery emits
`epoch_advanced` and `recovery_completed` in the same transaction, so it
sends both.

**Lookup.** The vault keeps each account's alert contacts under

```text
lookup = HMAC-SHA-256(k_alert, "nido/email-recovery/v1/alert-lookup" || account contract id)
```

where `k_alert` never leaves the sealed vault that holds the addresses
(§10.5). For each event the vault computes `lookup` for the account in
topic 1 and finds the record; an observer of the stored records without
`k_alert` cannot list which accounts have alerts **[built, tested]**
(`infra/email-alerts/src/vault/keys.ts`; `test/custody.test.ts` recomputes
it). When email is a recovery factor, a second channel (Web Push to a
passkey device) is required (§9.3 rule 2, §10.3).

The service is `infra/email-alerts` (host and vault) with the browser side
in `packages/email-recovery` and every third party mocked in
`packages/email-mocks`. What is built, what is mocked, and what is only
specified is listed per subsection.

### 10.1 The verification code

Every alert carries a 6-digit code that identifies what it is about. The
user compares it with the code the wallet shows for the attempt (or
change, or epoch) the wallet knows about; the alert itself never names the
account.

```text
k_code  = HKDF-SHA-256(ikm = account_code, salt = "", info = "nido/email-recovery/v1/alert-code-key", L = 32)

subject = 0x01 || BE64(attempt_id)     attempt_begun, attempt_authorized, attempt_cancelled, recovery_completed,
                                       email_vote_recorded, email_cancel_recorded,
                                       attempts_many (the attempt whose count raised it)
        / 0x02 || BE64(epoch)          epoch_advanced
        / 0x03 || digest               change_evidence_recorded, email_change_recorded (the 32-byte change digest)

mac     = HMAC-SHA-256(k_code, "nido/email-recovery/v1/alert-code" || network_id || controller || account || subject)
code    = BE64(mac[0..8]) mod 10^6, written as 6 digits with leading zeros, shown "123 456"
```

`network_id` is `sha256(network passphrase)`, `controller` the 32-byte
contract id of the controller that emitted the event, `account` that of
topic 1.

- **Who computes it.** The vault, with the `k_code` the wallet registered
  sealed at enrollment (§10.3). Any wallet that holds `account_code`, which
  the email factor needs anyway (§5.1), computes the same code; a
  recovering device that lost the passkey does too.
- **What it hides.** Without `k_code` the code is unpredictable. The
  sending service and the user's mail provider see the code but cannot
  match it to an on-chain attempt, which would undo the blinding of §4.2;
  nobody can choose a statement or attempt to produce a given code.
- **What it is not.** It does not authenticate an alert: alerts carry no
  link to act on, so a forged alert can only make the user open the wallet,
  which reads the chain. Nor does a matching code show that an attempt is
  the reader's own: anyone holding `account_code`, including someone who
  talked the user into reading it out (§11.4), computes the same code for
  their own attempt. So no alert says that a matching code means nothing
  needs doing; the push to a passkey device leads with cancelling (§10.6). A
  recovery that does not use the email factor needs `account_code` (the
  recovery kit or the backup of §5.6) to show the code.
- `deriveAlertCodeKey` and `alertCode` in `packages/email-recovery/src/alertCode.ts`
  are the only implementation; the vault imports them **[built, tested]**
  (`test/alertCode.test.ts` checks them against an independent `node:crypto`
  computation; `infra/email-alerts/test/alerts.test.ts` and
  `test/e2e.test.ts` check that the email and the push carry the code the
  wallet computes).

Test vector: `account_code` = bytes `01..10`, `network_id =
sha256("Test SDF Network ; September 2015")`, controller = 32 bytes `c1`,
account = 32 bytes `a1`, attempt id 1:
`k_code = a9045e1ee8c9fd6654033c8148a2569407441e29fefa90dc3ce38b35e03398e0`,
code `169328`.

The choice of derivation is open (§13 question 8).

### 10.2 The alert service (host)

The host is untrusted: it never holds an address, and a lying or stopped
host can suppress alerts but cannot read or redirect them. It
**[built, tested]** (`infra/email-alerts/src/service.ts`):

- **Watches** the controller with Stellar RPC `getEvents`, filtered only by
  contract id (so no query singles out an account), in pages, with a
  stored cursor. A page is handled in order; each event's id is recorded as
  handled in the same atomic state write (temporary file, `fsync`, rename)
  that stores the vault's sealed output, and the cursor moves only after
  the whole page. The watcher is caught up when the cursor's ledger reaches
  the latest ledger: one request scans at most 10,000 ledgers
  (observed on `soroban-testnet.stellar.org` and reproduced by the mock), so
  a short page does not mean caught up. The client's requests were run
  against that RPC, which accepted them and returned events of the shape the
  watcher decodes.
- **Never misses or repeats an alert.** After a restart it resumes from the
  cursor; a crash after the vault sent but before the host stored the
  answer re-dispatches the event, and the vault's delivery log refuses a
  second send of the same (event, contact, channel). A failed alert goes to
  a retry queue with exponential backoff (30 s doubling, at most 1 h)
  without holding back later events.
- **Tracks authorized attempts** per account from `attempt_authorized` until
  `attempt_cancelled`, `recovery_completed`, or `expires_at`.
- **Relays** wallet requests to the vault with the account's chain state:
  the latest ledger, whether an attempt is authorized, and the account's
  administrative passkeys, read with `simulateTransaction` of the account's
  `installed_rules()` (every `External` signer on a non-recovery rule that
  covers calls to the account itself: a `Default` rule or a `CallContract`
  rule naming the account; Nido's documents scope the admin rule as
  `CallContract(account)`). The read is tested against the recorded
  `installed_rules()` of a real account on the integration-test host, served
  through the RPC mock's `simulateTransaction`; it has not been run against
  a live network.
- **Matures** contact changes (§10.3) when they are due.
- **Finds email votes in transactions, per vote.** Perch emits no event
  when a guardian's vote is recorded on an attempt below quorum, nor for a
  vote to cancel or an approval of a change. Every such vote by a contract
  guardian is a successful transaction that carries the guardian's Soroban
  authorization entry for the controller's `submit_guardian` or
  `approve_change` (`require_auth_for_args((digest,))`, §8.3), and the
  attempt it changed is in the transaction's meta. So each poll the host
  also reads the next page of every transaction on the network with Stellar
  RPC `getTransactions` and `xdrFormat: "json"`, under its own cursor; the
  method has no filter, so the query singles out nothing, and the RPC
  decodes the XDR, so a transaction using XDR newer than the host's SDK
  still reads. In each, `src/votes.ts` takes every authorization entry whose
  credentials name a contract and whose invocation tree (root or any
  sub-invocation, so a vote nested under another contract's call counts)
  calls one of those two functions of the controller, and the `Attempt`
  values (`id`, `state`, `guardians`, `cancel_guardians`) the transaction
  wrote. A voter is the account's email guardian when its contract instance
  runs the email guardian's wasm (read once with `getLedgerEntries`) and
  its `config()` names this controller and the account (read once; both
  are immutable). For an account the vault holds contacts for, the vault
  sends, on every channel, `email_vote_recorded` for a written attempt still
  `Collecting` that lists the guardian among its `guardians`,
  `email_cancel_recorded` for one listing it among its `cancel_guardians`,
  and `email_change_recorded` for `approve_change`. A vote that authorizes
  the attempt is alerted as `attempt_authorized`. A vote whose meta places
  no attempt has its account reconciled on the next poll. How many attempts
  are open does not change what the host reads: an attacker who opens
  attempts after the target pays a fee for each and hides nothing
  (`griefing-then-vote`). **Latency:** the alert follows the vote by at
  most one polling interval plus the reads; on the mocks of
  `test/liveness.test.ts` the vault's answer comes within milliseconds, and
  on the local network the attack suite records it per run
  (`inbox-email-vote-alerted`, `griefing-then-vote`). **[built, tested]**
- **Counts open attempts.** For `attempt_begun` on an account the vault
  holds contacts for, the host reads the attempt's evidence deadline
  (`attempt`) and has the vault count it. The vault keeps, sealed, the
  open attempts with the latest deadlines (at most `MANY_OPEN_ATTEMPTS + 1`,
  enough to tell when more than `MANY_OPEN_ATTEMPTS` = 8 are open) and,
  while more are open, sends `attempts_many` on every channel under one
  delivery id per account and 24 hours. **[built, tested]**
- **Reconciles from controller state** on its first poll, every 6 hours
  (`RECONCILE_EVERY_MS`), and after the RPC refuses a cursor (events or
  transactions aged out of retention; both cursors restart together). For
  each account the vault holds an active contact for, it reads the
  controller's persistent state: the authorized attempt (`activity_gate`),
  with an email vote to cancel it, and every attempt still open, paging
  down from the newest (`next_attempt_id`, `attempt`, `epoch`) until one is
  gone, of another epoch, or a `Collecting` one past its evidence deadline:
  within an epoch the evidence windows close in id order, and attempts of
  an earlier epoch are dead. An authorized attempt is alerted, and email
  votes (on the attempt or to cancel it) on open attempts, under the same
  delivery ids the stream uses (§10), so nothing is sent twice; open
  attempts are counted. A completed recovery the stream missed is not
  re-alerted: reconciliation restores the alerts that can still change the
  outcome. How many attempts are open bounds the reads, as the attacker's
  fees bound how many there are. **[built, tested]**
- **Raises a lag alarm** (the log, an `onAlarm` hook for an operator's pager,
  and `GET /v1/health`) when its cursor is more than 720 ledgers (an hour)
  behind the chain, once per episode, and when the RPC refuses its cursor;
  it then resumes at the oldest ledger the RPC keeps (`getHealth`) and
  reconciles. A stopped watcher cannot raise an alarm itself:
  `GET /v1/health` reports its last poll for a monitor outside it (not
  built). **[built, tested]**
- **Probes push subscriptions** through the vault each poll, and relays
  each device's signed acknowledgement of a probe (`POST /v1/ack`, at most
  30 per client per hour) (§10.6).

`infra/email-alerts/test/liveness.test.ts` pins the email-vote alert (once,
on every channel, with the attempt's code; under forty newer attempts,
reading no attempt to find it; nested under another contract's call; not
for another guardian's vote, a failed transaction, or a vote that
authorizes), the cancellation and change alerts, the many-attempts alert, a
vote the meta does not place, the restart after the events aged out of
retention (one alarm, resume, one alert from controller state),
reconciliation paging through forty open attempts and stopping at the first
closed one, the shared delivery id of a reconciled and a streamed alert, the
lag alarm, and `chainReads` against the RPC mock in Stellar RPC's
encodings. The RPC mock serves `getTransactions` in base64 and in
stellar-xdr's JSON (`packages/email-mocks/src/stellarRpc.ts`).

**The wallet's own read.** Independent of the alert service, the wallet
reads the account's live attempts from the controller whenever it opens (the
home page) and on the recovery settings page: the authorized attempt from
`activity_gate` and every collecting attempt still live, paging down from
the newest, 16 at a time, until the first collecting one that is not live
(`readLiveAttempts` in `packages/passkey-sdk/src/perch/liveAttempts.ts`).
It lists those the email helper voted on (or voted to cancel) first, then
authorized ones, then any with an approval; with more than
`MANY_OPEN_ATTEMPTS` open it shows a warning above the list. A device
holding the account's passkey is told it does not need a recovery and
offered the owner's cancellation; a collecting attempt without approvals
shows as a quiet notice (`liveAttempts.ts`, `liveAttempts.test.ts`)
**[built, tested]**. A stopped or lagging alert service, or many attempts
opened after the one that matters, therefore cannot hide an attempt from an
owner who opens the wallet within the delay (`griefing-then-vote` runs the
wallet's own `readLiveAttempts`).

Residual: public RPCs keep a bounded history (120,960 ledgers by default,
for events and for transactions alike; `soroban-testnet.stellar.org`
answered `getTransactions` with exactly that window on 2026-11-02), which
equals the email-plus-delay profile's minimum delay. Reconciliation recovers
authorized attempts and email votes after a longer outage; it reads only
accounts the vault holds contacts for. Reading every transaction costs the
host the network's throughput in bandwidth (not run against mainnet here).

### 10.3 Alert contacts

A contact is an address plus, optionally, Web Push subscriptions (one per
device, each with the public half of the device key the wallet's service
worker made for it, an uncompressed P-256 point that signs probe
acknowledgements, §10.6), `k_code`, the purposes (bit 0: security alerts,
always set; bit 1: product updates), and the version of the consent text the
user saw. The wallet seals it to
the vault with HPKE (RFC 9180, base mode, DHKEM(P-256, HKDF-SHA256),
HKDF-SHA256, AES-128-GCM, `info = "nido/email-recovery/v1/vault-request"`)
after verifying the vault's attestation (§10.5).

**Owner authorization.** Every registration, replacement, removal, push
update, and status read carries a WebAuthn assertion (W3C WebAuthn Level 3 §7.2) by one of the
account's administrative passkeys over

```text
challenge = sha256("nido/email-recovery/v1/alert-contact/" || op || account || contact
                   || sha256(envelope) || BE32(purposes) || BE32(consent_version) || nonce)
```

with `op` one of `register`, `replace`, `remove`, `push`, `status`;
`contact` the 16-byte id of the new contact (or of the one to remove or add a
device to; 16 zero bytes for `status`); `nonce` 32 bytes the vault
issued, single use, valid 10 minutes (`remove`, `push` and `status` sign
purposes and consent version 0). The vault checks the assertion as the WebAuthn verifier of Perch
accounts does on chain (type `webauthn.get`, the challenge, UP and UV set,
BS only with BE, P-256 over `authenticatorData || SHA-256(clientDataJSON)`,
low-S) plus the relying party (`rpIdHash = SHA-256(rpId)`, an allowed
origin), and that the key is in the signer set the host relays. A lying host
could relay a false signer set; that host can already suppress every alert,
so the check defends against third parties, not against the host.

**Rules** **[built, tested]** (`infra/email-alerts/src/vault/vault.ts`,
`test/contacts.test.ts`):

1. A new contact receives alerts only after its email confirmation: the
   vault mails a 6-digit code, valid 72 hours, five attempts.
2. Registration is refused while the account has a live contact; changing
   it is a replacement.
3. Replacing or removing a contact takes effect `CONTACT_CHANGE_DELAY_SECONDS
   = 1,209,600` (14 days, longer than the 7-day minimum delay of §9.3 rule
   3) of ledger close time after the request; adding a push device does not
   wait (rule 8). The host relays the latest
   ledger's close time as Stellar RPC `getEvents` reports it
   (`latestLedgerCloseTime`), so the window keeps its length whatever the
   network's target ledger close time; a change sealed with only a ledger
   number (`maturesLedger`) still matures by that ledger number
   (`changeDue` in `infra/email-alerts/src/vault/vault.ts`). With ledgers
   closing every second, a removal still waits the full 14 days: one second
   short it is pending, at the deadline it applies (`test/contacts.test.ts`,
   "the clock contact changes mature on").
   Until then the old contact keeps receiving alerts, and it is told about
   the change at once, by email and push. A replacement whose new contact
   was not confirmed by then is dropped.
4. Removal is refused while a recovery attempt is authorized, and a removal
   that matures while one is authorized waits until it ends.
5. When a change matures, the vault re-checks that the authorizing passkey
   is still an administrative signer. A completed recovery that replaced it
   drops the change.
6. A contact whose account has an email guardian must include a Web Push
   subscription (§9.3 rule 2). Both the wallet helper and the vault refuse
   one without.
7. `status` answers each contact's id, state, best push state (`live`, then
   `unacknowledged`, then `lapsed`, or `none`), each device (`id`, the hex
   of the first 8 octets of `sha256(endpoint)`, which the device computes
   for itself; its state; when it was added and last acknowledged a probe;
   when it lapsed) and any pending change, never the address or an
   endpoint; the host relays the answer, so it learns that account's
   channel states.
8. `push` adds this device's subscription, with its device key, to an
   existing contact, at once, whatever its other devices do: adding a
   device takes no alert away from the owner, and whoever holds an
   administrative passkey controls the account anyway. The same endpoint
   again replaces its keys; lapsed devices make room first; a contact holds
   at most `MAX_PUSH_DEVICES` = 4. The address is told at once
   (*notifications added to a device*). Only replacing or removing the
   contact, and with it every device, waits under rule 3.

Rules 7 and 8 are tested in `test/liveness.test.ts` ("status names each
device; push adds a device at once, whatever the others do, and tells the
address", and the switched-phone case). The wallet helpers are
`packages/email-recovery/src/enrollment.ts` (`statusRequest`,
`pushUpdateRequest`, `probeAckMessage`; round trips in
`test/enrollment.test.ts`) and
`packages/frontend/src/lib/recovery/emailAlerts.ts` (`alertChannels`,
`addThisDevice`, and `deviceChannel`, which compares this device's current
subscription with the one it registered and asks the service worker when it
last acknowledged a probe). The settings page shows the channel as
`channelView` (`emailModel.ts`) reads it: on a device the vault lists as
live, or that acknowledged a probe within `RECENT_ACK_MS` (60 days), *they
reach this device*; on another device, where notifications go (since when)
with *Add this device*; with no live device, rule 2 broken
(`settingsEmail.test.ts`).
`recoverySpec` refuses an email guardian without a declared second channel
(§9.3 rule 2). The wallet's enrollment flow (§5.4) registers the contact
with a Web Push subscription for the vault's attested VAPID key, confirms it
with the emailed code, and only then applies the document that declares
`secondAlertChannel: 'web-push'`; the wallet's service worker
(`packages/frontend/public/sw.js`) shows each push with its code and opens
the wallet's own security page on a click, never a link from the payload;
the web app manifest (`manifest.webmanifest`) makes the wallet installable,
which iOS requires for Web Push **[built, tested]** (the end-to-end test of
§12, with the push-service mock's subscription standing in for the
browser's).

**The relying party is the account's subdomain.** A Nido passkey's RP ID is
its account's own subdomain (`<account>.<apex>`, the `C...` address in
lowercase). With the wallet's apex configured, the vault requires the
assertion's `rpIdHash` and origin to be those of the account the request
names, so a passkey made for one account's subdomain cannot authorize
another account's contact **[built, tested]** (`relyingPartyFor` in
`infra/email-alerts/src/vault/webauthn.ts`; `test/inbound.test.ts`).

### 10.4 The enclave-image registry

`contracts/enclave-image-registry` (crate `nido-enclave-image-registry`) is
the public record of which enclave images may hold the vault key
**[built, tested]** (`src/test.rs`, 15 tests; wasm 10,584 bytes optimized
**[measured]**):

- A fixed multisig (1 to 10 signers, `threshold` set at construction; no
  admin, no upgrade entry point) votes with `approve(signer, measurement)`.
  The first vote is the proposal (`measurement_proposed`); every vote emits
  `measurement_approved`.
- The vote that reaches the threshold queues the measurement with
  `active_from = T + TIMELOCK_SECONDS`, where `T` is the ledger's close time
  and `TIMELOCK_SECONDS = 1,209,600` (14 days), and emits
  `measurement_queued`. Every time the registry records (`proposed_at`,
  `active_from`, `activated_at`, `revoked_at`) is a close time in Unix
  seconds, measured on the clock of §7.6 "Clock".
- From a ledger whose close time is at or past `active_from`, anyone may
  call `activate` (`measurement_activated`). `is_active(measurement)` is
  true only from then. The unit tests pin the boundary one second before and
  at `active_from`, and show the timelock holding in seconds when five times
  the ledgers of 14 days at 5-second ledgers close inside it
  (`the_timelock_follows_close_time_not_ledger_count`).
- `threshold` signers may `revoke` at any stage; it takes effect at once and
  is final (`measurement_revocation_voted`, `measurement_revoked`).

```text
measurement = sha256("nido/email-recovery/v1/enclave-image" || PCR0 || PCR1 || PCR2)
```

over the 48-byte SHA-384 registers `nitro-cli build-enclave` reports for the
image. PCR3, PCR4, and PCR8 are not part of it, so a release policy never
trusts only a signing certificate. The integration-test host runs the
registry's whole lifecycle from its wasm (`email_alerts.rs`), advancing
the close time 14 days, and the custodian mocks read activation and
revocation from its events: a custodian trusts `measurement_activated`,
which the contract emits only once the timelock has passed, and does not
recompute the timelock itself (`infra/email-alerts/src/registryView.ts`).

The 14-day public timelock is a contract rather than a policy of the
custodians so that every approval is visible on chain, to anyone, before it
can take effect, and so that no custodian can shorten it. It is measured on
ledger close time rather than in ledgers so that a lower target ledger
close time cannot shorten it either: the contract has no setter, and a
ledger count would be fixed for its lifetime.

### 10.5 The sealed vault

**Keys.** One 32-byte master secret `K`; everything else derives from it
with `HKDF-SHA-256(ikm = K, salt = "nido/email-recovery/v1/vault", info)`:
the HPKE key pair wallets seal to (`info = "hpke"`, then RFC 9180
`DeriveKeyPair`), `k_alert` (`"alert-lookup"`), `k_store` (`"store"`), and
the VAPID key (`"vapid"`, 48 bytes reduced into `[1, n-1]`). The vault id is
`sha256("nido/email-recovery/v1/vault-id" || HPKE public key)`.

**Attestation.** The enclave answers a wallet's 32-byte nonce with an AWS
Nitro Enclaves attestation document (COSE_Sign1, ES384, the CBOR fields of
AWS's attestation process document) whose `public_key` is the HPKE key
(DER SubjectPublicKeyInfo) and whose `user_data` is CBOR `{purpose:
"nido-alert-vault/v1", vapid}`. The wallet verifies it as AWS prescribes
(the certificate path to the pinned root, validity, basic constraints and
key usage, the COSE signature, the field rules) and also requires its own
nonce, a timestamp at most 5 minutes old, a non-debug enclave (PCR0 not
zero), and a measurement it reads as active in the registry
**[built, tested]** (`packages/email-recovery/src/attestation.ts`; 25
refusal cases in `test/attestation.test.ts`). An absent optional field may
be `null`, as the NSM writes it. The NSM and its PKI are a
TEST-ONLY mock in AWS's published format with a test-only CA chain
(`packages/email-mocks/src/nitro.ts`).

**Custody.** `K` is split 2-of-3 with Shamir's scheme over GF(2^8)
(`shamir-secret-sharing` 0.0.4) across three custodians:

- *Genesis.* The enclave draws `K` and deposits share `i` with custodian
  `i`, HPKE-sealed to the custodian's key, under an attestation carrying the
  custodian's single-use nonce and `user_data = {purpose:
  "nido-share-deposit/v1", vault: vault id}`. A custodian never replaces a
  share it holds.
- *Restore* (restart or a new image). The enclave attests with each
  custodian's nonce, an ephemeral HPKE key as `public_key`, and `user_data =
  {purpose: "nido-share-request/v1", vault}`. Each custodian verifies the
  attestation independently, requires the measurement to be active in the
  registry, and returns its share sealed to the ephemeral key (`aad = nonce
  || vault`), the shape of AWS KMS's attested recipient. Two shares that
  re-derive the vault id reconstruct `K`; a wrong share is detected and the
  third custodian is asked.

**[built, tested]** for the vault side (`src/vault/custody.ts`,
`test/custody.test.ts`); the custodians are TEST-ONLY mocks
(`packages/email-mocks/src/custodian.ts`) that check attestations with an
independent verifier on `node:crypto`. Who the custodians are, and their
production protocol, are open (§13).

**Records at rest.** The host stores each account's record under its
lookup as `nonce || AES-256-GCM(k_store, nonce, CBOR(record), aad =
"nido/email-recovery/v1/record" || lookup)`, and the delivery log likewise.
A restarted vault loads them after restoring `K`.

**What is not built.** The production NSM binding (`/dev/nsm`), the vsock
channel with TLS terminating inside the enclave, and a reproducible enclave
build that yields the PCRs. In tests the vault is a separate Node process
reached over IPC (`ProcessVault`).

### 10.6 Sending

**Email.** Lettermint's Sending API (`POST /v1/send`,
`x-lettermint-token`, an `Idempotency-Key` per (event, contact) that makes a
retry within 24 hours return the original response), two attempts; then
Scaleway Transactional Email (`POST
/transactional-email/v1alpha1/regions/fr-par/emails`, `X-Auth-Token`), two
attempts. A 429, a 5xx, or a network error is retried; anything else fails
over at once. Both are EU-owned services; the mocks follow Lettermint's
published OpenAPI document (version 0.0.1) and Scaleway's generated SDK, and
cite them **[built, tested]** (`src/vault/send.ts`,
`packages/email-mocks/src/sending.ts`). Scaleway has no idempotency key, so a
Lettermint request that was accepted but whose answer was lost can be sent
again through Scaleway.

**Web Push.** RFC 8030 push requests (`TTL` 7 days and `Urgency: high` for
required alerts, a `Topic` per event so a resend replaces an undelivered
copy), RFC 8291 message encryption (one `aes128gcm` record; the
implementation reproduces RFC 8291's example byte for byte), and RFC 8292
VAPID (an ES256 JWT for the push service's origin, valid 12 hours, `sub` a
`mailto:` URI) **[built, tested]** (`src/vault/webpush.ts`). A required
alert goes to every device of the contact whose subscription is not gone,
each delivery logged per device. A 404 or 410 marks that device's
subscription gone (lapsed); email continues, and the contact's address is
told once (*notifications stopped*), with what to do.

**Liveness probe, acknowledged** **[built, tested]**. A push service
accepts a message for any valid subscription, whether or not the device is
on (RFC 8030), so its acceptance shows that the subscription exists, not
that alerts reach the owner: a phone switched off, retired or in a drawer
keeps a subscription that is accepted. Each device is therefore probed every
30 days (`VaultConfig.probeIntervalMs`, default `PROBE_INTERVAL_MS`; one
value) with an RFC 8030 push kept a week for a device that is offline
(`TTL` 604,800 s), `Urgency: low`, `Topic: probe` (a newer probe replaces an
undelivered one), payload `{v, kind: "probe", probe}` with a fresh 16-octet
probe id. The service worker shows it as a notification that asks to be
tapped (*Nido: tap to confirm your alerts*; never "nothing to do"); a tap
signs `"nido/email-recovery/v1/probe-ack" || probe id` with the device key
(ECDSA P-256 over SHA-256, `r || s`, the device key's private half made by
WebCrypto, not extractable, kept in the worker's IndexedDB) and posts
`{probe, signature}` to `POST /v1/ack`. The vault checks the signature
against that device's stored key and takes each probe id once; an
acknowledged device is live again. A device that acknowledged none of
`ACK_MISSED_PROBES` = 2 probes the push service accepted, each given a full
interval, is *unacknowledged* when the next probe is due: the contact's
address is told once (*notifications not confirmed*), alerts still go to
it, and the wallet treats it like a lapsed one for rule 2 (§9.3) until it
acknowledges again. A 404 or 410 to a probe marks the device lapsed. A probe
the push service cannot answer is tried again an hour later. The probe
counts are all the host learns. This shows that a device and its browser are
alive and that someone tapped, not that the person read an alert. The
trade-off: WebKit revokes a Safari or iOS subscription whose pushes show no
notification ("Meet Web Push", https://webkit.org/blog/12945/meet-web-push/),
so the probe is visible; at the monthly default it shows 12 a year and marks
a device that stopped acknowledging when the third probe after its last
acknowledgement is due, 60 to 90 days after it stopped; a shorter interval
finds it sooner and shows more (`test/liveness.test.ts`,
"probes each device monthly…", "the owner switched phones…", "the probe
interval is one configuration value"; `packages/frontend/src/lib/recovery/serviceWorker.test.ts`
runs `public/sw.js`).

**Content.** Generic text that never names the account, the address, or the
attempt; the code of §10.1; the wallet's canonical origin as plain text;
no link to act on (`src/vault/content.ts`). The push payload is
`{v, kind, title, body, code}`. A push goes only to devices the owner set up
for alerts, each added with an account passkey, so the push for
`attempt_authorized` and for an email vote leads with what the vault knows
and with cancelling: *This is the device you set up recovery alerts on. If
you can still sign in to your Nido, you do not need a recovery: cancel it
unless you are deliberately replacing your passkey.* (The vault cannot know
whether the device still holds the passkey.) Every required alert, email and
push, also pre-empts the caller who prepared its reader for it: *If someone
told you to expect this message, or to ignore it, they are trying to take
your account.* (`PREEMPT`): unlike the prepared email and the code-entry
warning, an alert reaches a phished owner (§11.4). The email says that a
matching code does not make the attempt the reader's own, and every email
ends by saying that Nido never asks anyone to send a recovery email,
approve a recovery, or read out a code, and that the recovery code is typed
only into the user's own Nido's recovery page, by the user, after losing
every device with the passkey: the one page that asks for it (`NEVER_ASKS`,
`PASSKEY_DEVICE_LEAD`; `test/alerts.test.ts`, "attempt_authorized: the push
leads with cancelling, both pre-empt a caller…", "every required alert
pre-empts a caller…") **[built, tested]**. Alerts and the probe look
different: an alert's title starts *Security alert:*, it carries a red alert
icon and stays until dismissed; the probe carries the wallet's own icon and
asks to be tapped (`sw.js`). A click on a recovery alert opens the wallet's
recovery page, where the cancel is.

### 10.7 Who sees what

| Party | Sees |
| --- | --- |
| The vault (attested enclave) | Addresses, push subscriptions, `k_code`, codes, `K` |
| The host | Which accounts register or change contacts and when (it relays their chain state), in memory which accounts have contacts (it reads their open attempts and matches email guardians' votes to them; its stored state holds only sealed records), the states of an account's push devices when the owner reads its status, that some probe was acknowledged and from which IP address, events and every transaction (as any RPC client sees them), sealed blobs and their sizes, the timing of outbound traffic |
| Custodians | One share each; the vault id; the enclave's measurement |
| Sending service (Lettermint, Scaleway; named in the consent text) | The address and the alert text, including the code |
| The user's mail provider | The alert text, including the code |
| Push service | The subscription endpoint and an encrypted payload |
| Stellar RPC | Bulk `getEvents` queries by contract and `getTransactions` queries of every transaction; `installed_rules` reads of accounts that change contacts; `attempt` reads of attempts opened on accounts with contacts, and `activity_gate`, `next_attempt_id`, `epoch` and `attempt` reads of those accounts in reconciliation (§10.2); `getLedgerEntries` and `config()` of guardians that voted |
| Anyone | The registry's approvals and activations |
| The vault, for inbound mail (§4.6) | The recovery or enrollment email in transit, so the address; the Subject value it routes by |
| The host, for inbound mail | Registration envelopes, inbox ids, sealed messages, their sizes and times, and the IP addresses that register and fetch them |
| The wallet's static host (the key list, §7.7) | That someone fetched the same file every user fetches |
| A DNS-over-HTTPS resolver, only after the user agrees (§7.7) | The user's IP address asking for one provider's key record: the provider, never the address |
| The user's mail provider, for the approval email | The Subject phrase and `T` or `E`, whose content links the email to no account (§4.2), and that the recovery address received a Nido email; the on-chain vote, or the guardian deployment after an enrollment email, follows within seconds, so a provider watching the chain can link the two by timing whenever few such transactions land in that window |

`infra/email-alerts/test/e2e.test.ts` checks the host, RPC, custodian, and
push-service rows: with the vault in its own process, none of the messages
to or from it, the host's HTTP bodies, its log, its state file, the RPC
calls, the custodians' decisions, or the push bodies contains the address
**[built, tested]**. The privacy claim this supports is scoped: Nido's
servers and staff cannot read the address; the sending service and the
user's mail provider necessarily can. It also rests on the enclave's
isolation and its custodians, on the recovery domain's MX, MTA-STS policy and
mail exchanger TLS keys staying the enclave's (the operator controls that
domain, and nothing built detects a change), and on users running the
published wallet build: A8, A10 and A11 in `research/email-recovery/claims.yaml`.

**Registry changes.** The key registry's events (§7.6) concern every
account at once, so they are announced publicly rather than per account.
Every one is emitted **[built, tested]**; the announcements are
**[specified]** (alert service).

| Event (topic 0) | Topic 1 | Announcement |
| --- | --- | --- |
| `key_proposed` | domain | **Required:** a key was proposed for the domain, with its modulus, so anyone can compare it with DNS; for an addition, the earliest close time it can activate at (`eligible_at` once approved) |
| `proposal_approved` | proposal id | Informational: approvals collected; when `approved`, the addition's timelock is running |
| `dns_attested` | domain | Informational; **required** when `observed_live = 0` on an addition: an attester did not see the proposed key in DNS |
| `key_activated` | domain | **Required:** the key is now accepted |
| `key_retired` | domain | Informational: the key leaves acceptance after the grace period |
| `key_revoked` | domain | **Required:** the key and every root holding it are refused |

## 11. Properties and their obligations

### 11.1 Assumptions

| Id | Assumption |
| --- | --- |
| A1a | RSASSA-PKCS1-v1_5 with SHA-256 and 2048-bit moduli is existentially unforgeable, and providers keep their DKIM private keys secret. |
| A1b | Each launch provider DKIM-signs a `from` field naming one of its mailboxes only when that mailbox's holder submitted the message. For the circuit's reading (§4.3, §4.5) this needs: (1) a submission with two `From` fields is refused or rewritten, or the provider authenticates the instance it signs (the bottom-most when `h=` names `from` once), and for a `From` with a display name the provider authenticates the angle-addr the circuit binds (a `From` that RFC 5322 readers read as several addresses, a group, another mailbox or none does not reach a proof: the circuit refuses it, §4.5); (2) sending as another address of the provider's domain requires proof of control of that mailbox; (3) an address is not reassigned, or a new holder cannot use it against an existing enrollment, which `account_code` provides (§5.1). The per-provider evidence, with a source for each cell or what would establish it, is `research/email-recovery/eval/parser/sender-authentication.md`; its unknowns are §13 question 23. |
| A2 | SHA-256 is collision resistant. |
| A3 | `P2` is collision resistant, and no input is known that it maps to `0` (the empty leaf); for the hiding claims (privacy, the blinded Subject, the salted pin) it is modelled as a random function. |
| A4 | The UltraHonk proof system with Perch's zero-knowledge flavor is knowledge sound and zero-knowledge, and the verifier contract embeds the email circuit's key. |
| A5 | The registry holds a leaf `(domain, key_hash)` only for a key that domain's operator controls. The registry contract reduces this to its governance (§7.6): a key enters only with `threshold` member approvals, after a public timelock of ledger close time (72 hours if `attest_threshold` attesters vouched it live in DNS, 7 days otherwise; wall-clock time under A9 (a)) during which `revoke_threshold` members can stop it; revocation is applied when a compromise is known. |
| A6 | `account_code` and `rho` come from a secure generator and stay with the user and the user's browser. |
| A7 | The enrolling wallet is honest at enrollment (it computes `C` and the pin from the real enrollment email). |
| A9 | **Timing.** (a) *Close time.* A ledger's close time tracks wall-clock time: stellar-core accepts a ledger only if its close time is later than the previous ledger's and at most 60 seconds past the validating node's clock (§7.6 "Clock"), and a quorum of validators keeps an honest clock. The registry's timelocks, grace, and proposal lifetime, the key pin, the enclave-image registry's timelock, and the vault's contact-change delay rest on (a) only, whatever the target close time. (b) *Ledger counts.* Perch's recovery delay, evidence window, and statement expiry are ledger counts, and Perch is used unchanged. Where one carries a security floor (the 7-day email-plus-delay delay, §9.3 rule 3), the wallet sizes it from the network's target ledger close time, `scp_timing.ledger_target_close_time_milliseconds` (CAP-0070; 5,000 ms on testnet and mainnet, read from both; at least 4,000 ms in protocol 23, a bound a later protocol may lower), and assumes ledgers close on average no faster than that target over the delay, since validators schedule each ledger that target after the previous one. A target lowered after a member was built shortens that member's delay in wall-clock time in proportion until it is rebuilt (§13 item 22); a core that closes faster than its target breaks (b): the local `stellar/quickstart --local` network reports 5,000 ms and closes about one ledger a second (measured: 30 ledgers in 30 seconds of close time), so there a 120,960-ledger delay lasts about 34 hours. |

### 11.2 Statements

Let `G` be an email guardian with configuration
`(account, controller, C, registry, pin, allowed, verifier)`.

1. **Soundness of the email factor.** If `G.__check_auth` succeeds on
   `(statement S, key_root R, proof)` in the context
   `controller.f((d,))` at ledger `L` with close time `T`, then, except with negligible
   probability, there is an email whose signed header block `H` carries a
   valid DKIM RSA-2048 signature (§4.3) under a key `n` with
   `leaf(domain, key_hash(n))` in the tree with root `R`; `R` is the pin
   root with `T ≤ pin.valid_until`, or a root the registry accepts at
   `T`; the `From` address of `H` is the address committed in `C`, and its
   domain is the leaf's domain and `d=`; and the Subject of `H` opens to
   `d = sha256(S)`, where `S` names `G`'s account, controller, and network,
   an allowed action, and a `valid_until_ledger ≥ L`. Through `S` the email
   binds the account, the new key (replacements and target, or new
   configuration, or Wasm hash), the nonce (attempt id or request id, and
   the epoch), and the expiry (§3.1). With A5 and A7, the `From` address is
   the enrolled address and `n` itself (not only its leaf) is a key that the
   leaf domain's operator controls.
2. **Privacy.** For any two addresses at allowlisted providers, a guardian's
   on-chain state and every approval it accepts (`C`, the pin root, the
   statements, the roots, the proofs) are computationally indistinguishable
   between the two addresses when `account_code` is uniform and unknown.
   What is revealed: that the account has an email guardian, its allowed
   actions, the time of each approval, and whether an approval used the pin
   or a registry root, and which one. Off chain, the provider sees `T`
   (§4.2), which hides `d`.
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
   a delay lasting at least 7 days at the network's target ledger close time
   when the member was built (`t · delay_ledgers ≥ 604,800,000` ms; 120,960
   ledgers at 5,000 ms) and a second alert channel. In wall-clock time the
   delay lasts 7 days under A9 (b).

### 11.3 Obligation table

Status: **proven** (formal proof), **tested** (this repository's tests),
**specified** (normative, not built), **assumed**. The proofs are Lean
theorems in `research/email-recovery/formal` about a model of the guardian's
checks (§8.3), the circuit relation (C1 to C6), Perch's controller and, for
privacy, the honest wallet; the model's agreement with the contracts is
tested, not proven (`research/email-recovery/formal/README.md`).

How the assumptions enter the theorems:

- **Hash breaks are explicit.** Where a theorem relies on A2 or A3's
  collision resistance, its conclusion is the property or a collision on two
  inputs the theorem computes from its data (for soundness: the extracted
  witness, the enrollment, and the tree of the accepted root; for replay: the
  encodings of the two statements the controller built), or, for A3's empty
  leaf, the extracted key's leaf input mapping to `0`. A break that only
  asserted some collision exists would be true of any hash function.
- **Knowledge soundness is per proof.** Theorem 1 holds for every extractor,
  as a function of the accepted approval's public inputs and proof: the email
  facts hold of the extracted witness, or the extractor fails on that accepted
  proof. A4 is that an efficient extractor exists for which an efficient
  prover gets a failing proof accepted only with negligible probability. No
  hypothesis asks for an extractor that succeeds on every accepted proof.
- **Privacy is proven in an ideal model.** The Lean statement is a simulation
  theorem: when the commitment and the pin root are handles independent of
  the secret and every honest proof is a simulator's output on its public
  inputs, the view of an adaptive adversary (the configuration, every
  approval the wallet hands out with its proof, every transaction, the
  guardian's verdicts, the controller's states and events) is computed from
  the handles and the public statements alone, for every private state of
  the wallet. The step from that ideal model to Poseidon2 and UltraHonk (A3's
  random-function model with A6, and A4's zero knowledge) is assumed.

| Property | Circuit obligations | Contract obligations (guardian) | Perch obligations | Assumptions | Status |
| --- | --- | --- | --- | --- | --- |
| 1 Soundness | C1, C2, C3, C4, C5, C6 | §8.3 checks 1 to 12; §8.2 wiring check; registry: §7.3 rules 1 to 5 and the same tree hashing as C6 (§7.2, §7.6 cross-check) | Statement construction from controller state (Perch §4) | A1a, A1b, A2, A3 (collision), A4 (soundness), A5, A7 | Proven with A5 and A7 as hypotheses, A4's break named per accepted proof, and A3's breaks named on computed inputs (`EmailRecovery.soundness`), for any reading of the header (the model's `Format` is a parameter); the conclusion fixes the `From` address, the account code and the key `(domain, modulus)`; A1a and A1b assumed, A1b reviewed per provider; guardian checks and registry rules tested; registry hashing tested against Noir; circuit built, C1 to C6 tested (§6.2, §6.4), not proven; the circuit's reading of headers tested against reference implementations on real mail and fuzzed headers (§12); real proofs verified on chain (§8.6) |
| 2 Privacy | Public inputs are exactly §6.1; nothing else is exposed | Stores `C` and a salted pin root, never an address or key hash; emits nothing | — | A3 (random function), A4 (zero-knowledge), A6 | Proven in the ideal model: an adaptive adversary's view, proofs included, equals a simulator's computed from the handles and the public statements, so any two addresses give the same view (`EmailRecovery.privacy_simulation`, `privacy_two_runs`); the step from the ideal model to Poseidon2 and UltraHonk rests on A3, A4, A6, assumed; structural lemma proven (the contracts store and emit nothing about the address beyond `C` and the pin root, `EmailRecovery.structural_noninterference`); guardian storage tested; the circuit's public inputs are exactly §6.1 (built, tested) |
| 3 Replay | C5 binds `d` | Checks 1, 2, 5, 6, 8, 12 | One vote per guardian per attempt and domain, or per change digest (Perch §6.3 T2, §5); attempt ids never reused (T1); epochs only grow (§3.3) | A2, A3, A4 | Proven with A2's break named on the two statements' encodings (`EmailRecovery.Perch.email_vote_replay`); tested (unit and integration) |
| 4 One-factor safety | — | The guardian is one address | Quorum (T4), delay (T5), cancellation (T6, T7) | A9 (b), for the wallet's delay floor in wall-clock time | Proven over all controller traces (`EmailRecovery.Perch.one_factor_safety`) and for the wallet policy (`one_factor_under_wallet_policy`, with the floor lasting 7 days at the target close time, `emailOnlyFloor_lasts`); on-chain part tested; wallet policy tested (§9.3); A9 assumed |

### 11.4 Adversaries beyond the protocol, and residual risks

The four properties are about the chain and the proof. Under the
email-plus-delay profile (§9.3 rule 3) email alone authorizes an attempt,
and what stops a wrongful one is the owner's cancellation within the delay,
which needs the owner to learn of it. The adversaries below act on that.
Each row of the attack suite named here runs on a local network
(`research/email-recovery/eval/README.md`).

**The inbox thief with the account code.** It authorizes an attempt under
email plus delay, cannot complete it within the delay, and deletes
everything sent to the inbox it holds. The owner learns of the attempt from
the push to the passkey device, from an alert address at another provider
(enrollment recommends one, §5.4), or by opening the wallet (§10.2). The
attack suite's worst case sends alerts to the stolen inbox itself: the push
alone reaches the owner, and a cancellation by the owner's passkey within
the delay succeeds (`inbox-email-plus-delay`). Under a quorum of two or
more, the email vote itself is alerted on every channel
(`inbox-email-vote-alerted`), also when 32 attempts were opened after the
voted one (`griefing-then-vote`), and so is an email vote to cancel, which
could stop the owner's own recovery (`inbox-email-cancel-alerted`).

**The social engineer.** It can get the user to send an email with a chosen
Subject to a chosen address, and to read out or type the recovery code (for
example posing as support). It needs no fake page: on its own device the
real recovery page opens a lost-key attempt that installs its key (opening
is permissionless), registers its own sealed-inbound value, and shows the
Subject, an opaque value the user cannot check. The user's email is then a
valid approval: property 1 binds the email to the statement, not to the
sender's informed consent. The six-digit code is no defence, since the
attacker holding `account_code` sees the same code (§10.1). Binding `To:` to
`RECOVERY_INBOX` would not stop it either: the email the attacker asks for
already goes there, and the attacker's own registration seals it to the
attacker (§4.6). What remains:

- the delay, and the owner's cancellation: a user who still holds the
  passkey is told by the push, and by the wallet when opened, that a device
  with the passkey needs no recovery and to cancel
  (`social-phished-holds-passkey`);
- other guardians: with a second helper required, the phished vote leaves
  the attempt collecting (`social-lost-devices-second-helper`);
- the alerts, which reach the victim after the vote: each required alert
  pre-empts the caller's script (*If someone told you to expect this
  message, or to ignore it, they are trying to take your account.*), and
  every email says that Nido never asks for an email or a code (§10.6);
- a reply to a phishing message is unprovable, because nothing may precede
  the Subject's phrase (§4.2).

The prefilled body line (§4.1) and the warning where the code is typed
(`codeEntryWarning`, §5.7) render on the attacker's screen in this attack,
not the victim's, so they are aids for an honest user, not defences against
it.

**Residual risk:** a phished user who has lost every device cannot cancel,
so under email plus delay the attempt completes once the delay passes
(`social-lost-devices-email-plus-delay`, run with the delay shortened
outside the wallet's policy so it elapses). A second helper, or the
`combined` mode, closes this. A code keyed by the owner passkey's PRF, which
a page holding only `account_code` cannot reproduce, is open (§13 question
8).

**Alert suppression.** A watcher stopped for longer than the RPC's history
misses the events and transactions; reconciliation from controller state
alerts the authorized attempt after the restart (`alerts-watcher-outage`),
and the lag alarm reports the gap (§10.2). Opening attempts hides no vote:
votes are found per vote, and reconciliation and the wallet page through
every open attempt (`griefing-then-vote`). A push subscription the push
service drops is found lapsed by the next probe or alert; a device that is
off, retired or never tapped keeps its subscription, so the probe asks for a
signed acknowledgement, and a device that gave none for two probes is
unacknowledged (§10.6). Either way the contact's address is told, and the
wallet treats the email helper as breaking rule 2 until a device receives
and confirms notifications again (§9.3). A new phone is added at once with
the passkey (§10.3 rule 8; `alerts-phone-switched`). **Residual risk:**
with alerts going to the stolen inbox and the push lapsed, or the only
subscribed device unacknowledged and unused, no alert reaches the owner
until the vault notices, which for an unacknowledged device takes up to
three probe intervals; only opening the wallet within the delay shows the
attempt (`alerts-lapsed-push`). A lying or stopped host can suppress every
alert (§10.2); the wallet's own read does not depend on it.

**Repeated attempts.** Anyone may open attempts at the cost of a
transaction fee. Each alerts nothing by default: the wallet lists them, each
granting nothing. More than `MANY_OPEN_ATTEMPTS` (8) open at once send one
alert a day on every channel, since many can hide one that matters
(`griefing-repeated-attempts`); they hide no email vote
(`griefing-then-vote`).

## 12. Measurements

All figures were read from runs in this repository, on the test host
unless a row names a local network or testnet. Alert figures are
**measured on mocks**: every service is a TEST-ONLY mock on the loopback
interface, so they show the service's own cost, not a provider's or a
network's.

| Figure | Value | Source |
| --- | --- | --- |
| Guardian wasm, optimized | 33,577 bytes | `just build-contracts` output for `nido_email_guardian.wasm` (local build; the CLI version recorded in the wasm metadata can change it by a few bytes) **[measured]** |
| Registry wasm, optimized | 68,899 bytes | `just build-contracts` output for `nido_dkim_registry.wasm` (same caveat) **[measured]** |
| Verifier wasm, optimized | 45,616 bytes | `just build-contracts` output for `nido_email_verifier.wasm` (same caveat) **[measured]** |
| Recovery circuit | 248,996 UltraHonk gates (109,809 ACIR opcodes), padded to 2^18; at a 1024-byte header bound 188,986, also 2^18 | `circuits/email-recovery/scripts/measure.sh` (`bb gates`), `circuits/email-recovery/MEASUREMENTS.md` **[measured]** |
| Proving one recovery email, native (`bb prove --zk`) | every core (18): 0.74 s witness (`nargo execute`), 0.94 s proving (0.93 to 0.97), 876 MiB peak; one thread: 4.64 s proving; the Performance-tier cores (the slower of the machine's two tiers, as macOS names them): 16.1 s on one thread, 5.60 s on four; at 1024 bytes 743 ms, 1,002 ms, 835 MiB | `research/email-recovery/eval/results/proving.json` (`just email-recovery-proving`): one circuit build (the committed artifact, its key checked against the verifier's circuit id), median and range of 5 runs, at a one-minute load average of about 6; a second run of the same build at load 5.4 (`proving-shared-load.json`) agrees within 2%, the Performance tier included; the 1024-byte figures `circuits/email-recovery/scripts/measure.sh`, median of 3 (load average 7 to 14) **[measured]** |
| Proving one recovery email, bb.js 0.87.0 in Node | one thread: 13.4 s proving (13.1 to 13.6), 1,386 MiB peak; 18 threads: 3.24 s (3.22 to 3.34), 1,662 MiB; the Performance-tier cores: 50.3 s on one thread, 19.0 s on four; at 1024 bytes 12.0 s and 2.8 s | same **[measured]** |
| Proving one recovery email in the browser: desktop | Chrome 151 (headless) on the same 18-core machine, the wallet's own prover worker on the recovery route's headers: one thread 8.37 s proving (8.32 to 8.50), 9.88 s from request to verified proof; 18 threads 1.44 s and 2.81 s; Barretenberg memory 757 / 791 MiB; peak renderer resident memory 1,432 / 2,586 MiB | `research/email-recovery/eval/browser-prover.md` (`measure-browser.mjs`), median and range of 5 warm runs, consolidated in `proving.json` **[measured]** |
| The same under DevTools CPU throttling 4x and 6x | proving unchanged (8.5 s on one thread, 1.5 s on 18): Chrome applies `Emulation.setCPUThrottlingRate` to pages only and refuses it for workers, where all proving runs; the page's main-thread probe slowed about 4x and 6x. A throttled desktop, and not a phone approximation | `browser-prover.md` **[measured]** |
| The same on the desktop's Performance-tier cores | Chrome under macOS background QoS (`taskpolicy -c background`), which runs it on the slower of the machine's two core tiers (6 Super, 12 Performance): one thread 32.5 s proving, 37.3 s total; four threads 10.3 s and 14.9 s; peak renderer resident memory 1,398 / 2,034 MiB. Desktop cores, the slower tier, not a phone | same **[measured]** |
| What a first proof downloads | 18,664,335 octets of proving inputs (the artifact, the key, and the CRS prefix), cached, so a retry downloads none of them; with the page and the prover's code (8,393,672 octets from the site, uncompressed: bb.js's and noir_js's wasm and scripts, the worker, the page) and the page's fonts (134,982), a first proof transfers 27,192,989 octets | `browser-prover.md` (the cold runs), `test/prover.test.ts`; the whole transfer `research/email-recovery/eval/results/first-load.json` (`first-load.mjs`: the benchmark page in a fresh headless Chrome profile, one thread, every response of the site counted at a proxy, the inputs as the prover counts them, other origins from Chrome's network log); a deployment that compresses its files transfers less **[measured]** |
| Phones | **Not measured.** No phone was available. `/security/recover/bench/` runs the same benchmark on any device, with no account, and prints copyable JSON; `just email-recovery-bench-phone` builds it as a self-contained directory (the page, its assets, the circuit and key, and the CRS prefix checked against the prover's pinned digests, read by the page through `?crs=`) and serves it over HTTPS on this machine's network addresses with the recovery routes' headers. `research/email-recovery/eval/phone/check.mjs` runs that build in headless Chrome (cross-origin isolated, the CRS from the build, both proofs verified); that is a check of the build, not a phone figure | — |
| Enrollment and recovery end to end on a local network | Passes in 1.7 minutes: in Chromium, the owner's Nido turns on recovery, enrolls an inbox (two groups of the recovery code typed back; the Gmail mock signs the enrollment email; the vault seals it back; the page checks it, warns when the alert address is the enrolled inbox, registers an alert contact at another address with Web Push, deploys the guardian with its pin, and lists it with a quorum of two); a new device opens a lost-key attempt, the page warns where the code is typed, prefills the warning line in the email's body and shows the pickup deadline, the vault seals the recovery email back, the page proves it in the browser and submits `submit_guardian`, the alert service alerts the email vote, the other helper approves, the alert email and push carry the code the page showed, and after the delay the page completes the recovery | `tests/e2e/local/email-recovery.local.spec.ts` (`just test-e2e-email-local`) on `stellar/quickstart --local` (core and RPC v29, protocol 28) with Perch's stack built for that network and Nido's contracts from source. Mocked (TEST-ONLY): the mail provider and MX, DNS, the sending services, the push service, the Nitro enclave and its custodians, and the enclave-image registry (a stand-in answering `is_active`, since its 14-day timelock cannot elapse locally); the test's passkeys are the repository's test authenticator. Not in CI **[built, tested]** |
| The circuit's header parsing on real mail | 5,154 DKIM-signed posts from all 11 launch domains (18 GNU mailing lists, October 2025 and May to October 2026), 5,327 signatures: the circuit and the reference (mailauth 8.0.4 strict mode for RFC 6376, node:crypto for RSA, Python 3.14's RFC 5322 reader for From) agree on every one. 4,619 are accepted by both with the same address and domain; 708 are refused by both: 316 do not verify under any known key (an archived copy whose signed fields the list changed, or a key no public source still holds), 229 signed blocks exceed `HEADER_MAX` (in 197 the longest signed field is `References` or `In-Reply-To`; the others sign a long `Cc`, `Autocrypt`, `Face` or `Mail-Followup-To`), 162 have a `d=` other than the From domain, 1 has two signed Subjects. The committed recovery artifact agrees with the harness on all 10,320 executions; the encoder's signed block equals the reference's for every signature; 592 signatures verify only under a key from zkEmail's public archive | `research/email-recovery/eval/parser/results/differential.json` (`just email-recovery-parser-check`). These are list archives' copies of ordinary posts, not the providers' outbound recovery mail; no Fastmail signature verifies under any key the DNS or zkEmail's archive holds, so Fastmail is tested on the refusing side only **[measured]** |
| Grammar-based fuzzing of the circuit's parsing | 50,000 seeded cases around the §4.5 From grammar and the §4.3 tag list (49,779 signatures, 51,814 circuit executions, 35 minutes on 18 cores), each compared with mailauth's strict RFC 6376 verifier and Python's RFC 5322 reader: 22,409 signatures accepted and 23,967 refused by both. Every From value the circuit accepts, Python reads as exactly the mailbox it binds; among the refused are 600 that Python reads as one mailbox but whose display name §4.5 excludes (of the 596 nothing else refuses, 498 hold a comment and 98 an RFC 2047 encoded-word with an `@`). The circuit accepts 2,692 that mailauth ignores for a defect in a tag the circuit does not read (§4.3), and refuses 711 that RFC 6376 allows, each for whitespace in a tag it reads (§4.3). The recovery artifact agreed with the harness on all 1,994 cross-checked signatures, and refuses each of the four From values of `from-finding.mjs` (an address list, an address before the angle-addr, a quoted word before an address, an unclosed quoted string) at the display-name check | `research/email-recovery/eval/parser/results/fuzz.json`, `results/from-finding.json` (`just email-recovery-parser-check`); seeded and reproducible case by case (`fuzz.mjs --show`); signed with a TEST-ONLY key **[measured]** |
| Attack suite on a local network | 70 scenario rows in eleven classes (forged emails, replayed emails and proofs, a wrong account or new key in the statement, stale or malicious registry keys, a compromised inbox, the alert path, phishing and social engineering, repeated attempts, provider header quirks, front-running, privacy on chain), each outcome as expected and each refusal named by its layer (circuit assertion, guardian check number, registry rule, Perch controller error, alert path); the three registry scenarios that need an elapsed timelock or grace period on the test host with the registry's real timelocks | `research/email-recovery/eval/README.md` (`just email-recovery-attacks`; `network/attacks.mjs` on `stellar/quickstart --local` at protocol 29 with mainnet's settings, every approval a real proof by bb.js in Node; `email_guardian.rs::registry_*`). Mocked (TEST-ONLY): the mail providers, DNS, the sending services, the push service, the enclave and its custodians, and the enclave-image registry (the end-to-end test's stand-in). In CI (`email-recovery-attacks.yml`) **[built, tested]** |
| Enrolling an account at mainnet's settings | minting the account 2,876,016 stroops, deploying its email guardian 1,609,367, the recovery document that lists it with one helper 6,949,238: 11,434,621 stroops (1.1 XLM), almost all of it rent (2,863,021, 1,603,056 and 6,918,606), since new entries live at least mainnet's 2,073,600-ledger minimum and the guardian and the account extend theirs to the maximum. The testnet recovery run's enrollment: 1,344,343, 1,997,088 and 5,711,756 | `research/email-recovery/eval/results/attacks-local.json`, medians over the attack run's 11 launch-domain accounts on the local network with mainnet's settings; testnet from `testnet.json` **[measured]** |
| One `submit_guardian` with an email approval on a local network | metered: 121.6 million instructions (121,576,077 to 121,664,431 across 20 votes, median 121,641,679), 12 entries read, 2 entries and 1,208 bytes written; 126,485,435 to 126,577,531 instructions declared after simulation, which the fee is charged on; 18,080-byte transaction around a 16,784-byte authorization entry; 83,125 to 83,153 stroops charged, 2,047 to 2,049 of them rent. The vote that authorizes an attempt with a 7-day delay also writes the authorized attempt: 122.5 million instructions (127,443,767 declared), 4 entries and 1,488 bytes written, 3,632,052 stroops charged, 3,545,582 of them rent | `research/email-recovery/eval/results/attacks-local.json`, read from each transaction's result and the host's `core_metrics` events, on `stellar/quickstart --local` at protocol 29 with mainnet's settings loaded (`eval/network/start-local.sh`, settings archived in `eval/results/settings/`); the approvals use the guardian's pin, so the registry is not called (spec §7.4) **[measured]** |
| One `submit_guardian` with an email approval on testnet | metered: 121,609,311 to 121,696,841 instructions across 6 votes, 12 entries read, 2 entries and 1,208 bytes written; 126,516,681 to 126,607,608 instructions declared; 18,080-byte transaction; 82,419 to 82,446 stroops charged, 1,333 of them rent; 2,215 to 3,397 ms from simulation to confirmation. The recovery run's vote: 121,675,439 instructions (126,586,879 declared), 82,440 stroops | `research/email-recovery/eval/results/testnet-votes.json` (`testnet/votes.mjs`) and `testnet.json` (`testnet/run.sh`), read back from Stellar RPC 30.0.0 (protocol 29). Both runs are of commit `ab274154` on `main`, each contract's wasm sha256 recorded, and read the deployed verifier's circuit id back (`a998d03e…`, this tree's verification key); every transaction's envelope, result and metadata XDR is in `testnet-xdr.json` (`testnet/evidence.mjs`). The approvals use the guardian's pin **[measured]** |
| The same vote's fee by component at mainnet's settings | 37,969 compute, 3,016 for the 2 entries and 1,208 bytes written, 36,419 history, 3,585 transaction size, 10 events: 80,989 non-refundable; 2,049 rent and the 100-stroop inclusion fee: 83,148 stroops, the Gmail vote's charge on the local network. Testnet charges the same components except rent (1,333: its minimum temporary lifetime is 720 ledgers, mainnet's 17,280) | `eval/fees/model.mjs` over each transaction's declared resources and the archived settings, which reproduces every fee charged in the evaluation's network runs to the stroop; table in `research/email-recovery/eval/README.md` **[measured]** |
| How many email votes a mainnet ledger holds | at most 12 (CAP-0063: 3 clusters per stage, each within 580,000,000 declared instructions, which 4 votes of about 126.5 million fill); 47 by transaction size, 245 by bytes written; 2.4 votes a second at 5-second ledgers. Past that, transactions compete on their inclusion fee; the resource fee is fixed by the settings | mainnet's settings (`eval/results/settings/mainnet.json`) and the local votes' declared resources **[measured]** |
| Votes against a registry root on a network | **Not yet measured; scheduled.** A registry root holds a key only after its addition's attested timelock, 72 hours of ledger close time. The local network's run (`eval/network/run-registry-root.sh`: one account per launch domain with no pin and one with the wallet's pin) and the testnet run (`eval/testnet/votes.mjs`) are enrolled; both were set up from commit `ab274154` and check the verifier's circuit id before they vote; their additions are eligible from close time 2026-11-05 13:01:51 UTC and 13:04:40 UTC, when they vote against the registry's root. Until then the registry-root figures are the test host's: the two `submit_guardian` rows below, whose approvals use a registry root, and `is_accepted_root` | — |
| One complete email-factor recovery on testnet | every step succeeded: mint, guardian deployment, the recovery document, `begin_lost_key`, the email vote, the helper's vote (which authorizes the attempt and pays its record's rent: 3,664,629 stroops charged, 3,653,812 rent), a 12-ledger delay (57,099 ms), and completion; 13,758,804 stroops charged over those 7 transactions; the account's document then holds the new passkey and not the lost one. An earlier run on the same Perch deployment found Perch's doc compiler and recovery controller archived and restored them first, one transaction per entry: 112,447,907 stroops over 4 transactions, 8.4 times that run's recovery (13,384,714); this run found them live | same, and `testnet-restorations.json` for the earlier run; deployment in `DEPLOYED.md`, "Email recovery (evaluation, TEST-ONLY)". Mocked (TEST-ONLY): the mail provider, DNS **[measured]** |
| A recovery with every entry it reads archived, at mainnet's settings | 7 transactions and 3,959,831,748 stroops (396 XLM), almost all of it rent to restore 28 entries for mainnet's minimum persistent lifetime (2,073,600 ledgers): the code of Perch's doc compiler, account, controller and WebAuthn verifier and of the email verifier, guardian and registry dominate, and three code entries exceed one transaction's limits (200,000 bytes read, 132,096 written), so they restore in RestoreFootprint transactions of their own. The same 4 steps with nothing archived: 5,237,377 stroops. Rent is priced at mainnet's rate today, the 1,000-stroop-per-KB floor, which holds while the average Soroban state stays at most 2.0 GB (1.718 GB when the settings were read); the rate grows with the average, to 5.5 times at 2.5 GB (21,776,595,086 stroops) and ten times at 3.0 GB (39,593,358,424). Whoever submits pays it, and a recovering user's new device holds no XLM: the wallet submits through the relayer, whose mainnet configuration spends at most 100 XLM a day (`infra/relayer/fly.mainnet.toml`), and it has no RestoreFootprint path; who pays an archived recovery on mainnet is open | `crates/integration-tests/tests/it/email_archival.rs` (`eval/archival.sh`): each step re-executed by the test host with every entry not yet restored archived, under mainnet's cost model and entry lifetimes, priced by `eval/fees/archival.mjs`; code entries sized for rent as the network sizes them (`eval/results/code-entries.json`). Not a network: no network here archives within a run **[measured]** |
| Keeping the contracts live, a year of rent at mainnet's settings | 3,304,297,283 stroops (330.4 XLM) for the email verifier (instance and code), the key registry (instance and code) and the guardian's code, shared by every account; 3,245,716 (0.32 XLM) for each account's guardian instance; Perch's controller, doc compiler, WebAuthn verifier and account code, which Perch's operator keeps, 8,677,150,521 (867.7 XLM). A code entry is sized for rent by its in-memory module, 9 to 26 times its entry here (the guardian's 33,672-byte entry rents as 320,239 bytes, Perch's doc compiler's 110,040-byte one as 2,431,469). Each keeper transaction pays about 1,240 stroops besides rent. At 5.5 and 10 times today's rent rate (an average state of 2.5 and 3.0 GB) the shared entries cost 18,173,606,450 and 33,042,915,617 a year, an account's guardian instance 17,845,716 and 32,445,716 | `research/email-recovery/eval/results/keeper-local.json` (`eval/network/run-keeper.sh`: the keeper, `eval/network/keeper.mjs`, run once on a local network with mainnet's settings, every extension's rent reproduced from the entry's size for rent); a year is 6,307,200 ledgers at 5 seconds **[measured]** |
| One `submit_guardian` with an email approval and a real proof, whole invocation on the test host | 121,799,565 to 121,883,583 instructions (30.4 to 30.5% of 400,000,000); 5.6 MB of memory; 14 entries read; 2 entries and 1,208 bytes written; resource fee without rent 94,419 to 94,478 stroops at the SDK's 2026-07-10 fee snapshot, across the 12 fixtures | `email_proofs.rs` (every launch domain and the 124-byte address), `cost_estimate()`; table in `research/email-recovery/eval/onchain.md` (`measure-onchain.py`) **[measured]** |
| The same call as a signed transaction | 131,172,469 to 131,248,057 instructions; footprint 12 read-only and 2 read-write entries; 18,148-byte envelope with a 16,784-byte authorization entry around the 16,224-byte proof; resource fee without rent 178,196 to 178,249 stroops at the SDK's 2026-07-10 fee snapshot; 82,530 at mainnet's archived settings (Gmail) | `nido_integration_tests::transaction::measure` in the same tests **[measured]** |
| `is_accepted_root`, accepted or refused | 565,410 / 568,054 instructions; 286,542 bytes of memory; 2 entries read; nothing written; no events; fee without rent 396 / 398 stroops | `dkim_registry_costs` **[measured]** |
| `propose_add` (computes the key hash over the 2048-bit modulus) | 9,347,998 instructions; 532,837 bytes of memory; 6 entries read; 3 entries and 1,596 bytes written; 744 event bytes; fee without rent 23,730 stroops | same test **[measured]** |
| `approve` | 669,842 instructions; 300,741 bytes of memory; 5 entries read; 2 entries and 496 bytes written; 208 event bytes; fee without rent 10,035 stroops | same test **[measured]** |
| `attest` (parse, checks, Ed25519 verification) | 1,163,336 instructions; 291,341 bytes of memory; 3 entries read; 1 entry and 444 bytes written; 412 event bytes; fee without rent 7,270 stroops | same test **[measured]** |
| `execute` of an addition (the leaf and the 16-level root recomputation) | 22,774,204 instructions; 1,068,056 bytes of memory; 37 entries read; 20 entries and 4,400 bytes written; 348 event bytes; fee without rent 102,662 stroops | same test **[measured]** |
| The approval that executes a revocation (removal, root recomputation, refusals) | 20,048,562 instructions; 880,742 bytes of memory; 39 entries read; 21 entries and 1,956 bytes written; 516 event bytes; fee without rent 103,549 stroops | same test **[measured]** |
| Enclave-image registry wasm, optimized | 10,584 bytes | `just build-contracts` output for `nido_enclave_image_registry.wasm` **[measured]** |
| `attempt_authorized` to the email accepted by the sending mock | 11 to 62 ms, median 16.5 (10 runs) | `infra/email-alerts/test/e2e.test.ts` (`NIDO_ALERT_MEASUREMENTS`), from the start of the watcher's poll to the Lettermint mock's receipt; Node 24.18.0, darwin arm64, a shared machine (load average about 45) **[measured on mocks]** |
| `attempt_authorized` to the push accepted by the push mock | 13 to 66 ms, median 19 (10 runs) | same **[measured on mocks]** |
| Reading the event to the vault's answer (email and push sent) | 13.7 to 27.7 ms, median 17.3 (10 runs) | same, `PollReport.latencyMs` **[measured on mocks]** |
| Vault restart: process start, shares from two custodians, reconstruction, unsealing | 147 to 238 ms, median 152 (10 runs) | same **[measured on mocks]** |
| Vault attestation document (16 PCRs, 3-certificate bundle) | 3,775 bytes | same **[measured on mocks]** |
| Contact registration request as the wallet posts it | 1,284 bytes of JSON | same **[measured on mocks]** |
| Web Push body (RFC 8291, one record) | 353 bytes | same **[measured on mocks]** |
| Lettermint request body of an alert | 1,076 bytes | same **[measured on mocks]** |

The `submit_guardian` figures include the proof verification: Perch's
controller and account, the guardian, the registry, and the verifier all
run as wasm, with each launch domain's committed proof. The test host's
reading is `cost_estimate()` of the invocation; the host enforces the
SDK's mainnet resource limits on every invocation, so the call fits them.
The transaction reading re-executes the call in a fresh host over a snapshot
of the test ledger with the signed authorization entry enforced, records the
footprint, builds the signed envelope, and prices it with
`compute_transaction_resource_fee`, transaction size included; its
instruction count is about 7.6% higher than the test host's, which the SDK
documents does not model some production work. Rent is left out of both.
The registry figures are the whole invocation of each entry
point from the registry's wasm (no entry was read from disk, so ledger
bytes read are 0 in every row), with the 3-of-5, 2-of-3 configuration of
`crates/integration-tests/src/email.rs`; `dkim_registry_costs` also asserts
loose ceilings on `is_accepted_root`, `attest`, and the activation. The fee
figures are the SDK's `cost_estimate().fee()`, which prices the measured
resources with the snapshot of mainnet's fee schedule of 2026-07-10 that
soroban-sdk 27.0.6 hardcodes, about twice mainnet's schedule as archived in
`research/email-recovery/eval/results/settings/mainnet.json`; they are not
network measurements. Rent is left out of them: every registry write extends
its entries to the maximum TTL, so the rent charged depends on the network's
maximum TTL (10,000,000 ledgers in this test ledger) and on how recently an
entry was last extended, and the SDK prices rent above the network's rate on
purpose. Network fees, rent included, are the local-network and testnet
rows.

Every network fee in this section is attributed to its components by
`research/email-recovery/eval/fees/model.mjs`, a port of the host's
`fees.rs` that computes a transaction's fee from its declared resources and
the network's archived settings; it reproduces the fee every transaction of
the evaluation's local-network and testnet runs was charged. The local
network runs mainnet's settings, so its fees are the mainnet projection.

Fee estimation through RPC simulation needs care: simulation that records
authorization does not run custom accounts' `__check_auth`
(`vendor/perch/AGENTS.md`), so a `submit_guardian` simulated without the
guardian's signed authorization entry omits the guardian's checks and the
proof verification. The transaction figures above enforce the entry and so
include both. So do the local-network and testnet figures: the evaluation
simulates every email vote with its entry enforced (`authMode: enforce`).

In production, alert latency adds the watcher's polling interval and the
providers' own delivery to these figures.

## 13. Open questions

1. **Key pin semantics.** v1 pins additively, fixed at construction, salted,
   with an expiry. Alternatives: a restrictive pin (only pinned keys,
   registry ignored), which makes a planted registry key useless but stops
   email recovery at every provider rotation until a new guardian is
   deployed; requiring both the registry and the pin, with the same
   rotation problem; a pin the owner can change after deployment, which
   would let anyone holding the owner key and `account_code` pin a key of
   their own and approve without the inbox.
2. **Pin lifetime.** The cap is 365 days (`MAX_PIN_LIFETIME_SECONDS`).
   The wallet deploys guardians with a 30-day pin (2,592,000 seconds of
   close time past the latest ledger's, `PIN_LIFETIME_SECONDS` in
   `packages/frontend/src/lib/recovery/emailConfig.ts`, one constant, applied
   by `pinValidUntil`) **[built, tested]**
   (`emailModel.test.ts`, "the key pin the wallet deploys"). Alternatives: 30 days, which covers the registry's 7-day
   timelock with margin and keeps the revocation window of §7.4 short; 365
   days, the cap, which keeps the enrolled key usable through the pin longest
   if the registry drops or delays it and leaves a revoked key usable through
   the pin longest; about 10 days, which covers the timelock with less margin
   and narrows the window further. Shorter pins mean the registry path must
   carry recoveries sooner after enrollment.
3. **Default allowed actions.** v1 deploys all five actions. Alternatives:
   initiation and cancellation only, or initiation only, with §9.3 rule 4
   preventing a lock-out.
4. **`account_code` backup.** v1 offers the passphrase-encrypted copy in the
   enrollment email and a recovery kit, both from one wallet component
   (§5.6). Alternatives: the code in plain text in the enrollment email (best
   recoverability; the provider can compute `C` and link the inbox to the
   account), or a recovery kit only (no copy at the provider; lost if the
   kit is lost).
5. **Registry parameters.** The registry is built with the defaults of §7.6;
   each is a constructor parameter.
   - *Grace period.* Built with 86,400 seconds (24 hours), capped at
     604,800 (7 days). Alternatives: 7 days, which strands fewer proofs made
     against a previous root but keeps a key its provider has blanked in DNS
     acceptable for a week unless it is revoked; or 1 hour, which shortens
     that window but can strand a user whose proof was made against the
     previous root.
   - *Revocation threshold.* Built with an emergency threshold of 2 of 5
     members, paired with the rule that a revoked key returns only through a
     new full-threshold addition on the 7-day path. Alternative: the full
     threshold (3 of 5), under which two members cannot block a provider's
     live key, and also cannot stop a key a threshold of members planted
     during its timelock or cut off a leaked key without a third approval.
   - *Who.* The five members, the three attester operators, and the
     resolvers each attester queries are not named.
6. **Provider details.** The circuit and the provider mocks agree on every
   launch domain's format, and `HEADER_MAX` (§6.3) is sized on those
   formats. Not yet confirmed against real provider mail: the exact domain
   allowlist per launch provider (for example whether secondary domains sign
   with their own `d=`), each provider's signed header block for very long
   addresses and display names, and whether each provider's stored or
   received copy keeps its `DKIM-Signature`. The circuit reads 5,327 real
   launch-provider signatures from public list archives as reference
   implementations do (§12); those are list copies of ordinary posts, so the
   points above remain open.
7. **`RECOVERY_INBOX`.** How its mail reaches the browser is §4.6 (sealed
   inbound by default, `.eml` import as the alternative). Open: the address
   itself (a deployment parameter; the tests use `recover@recovery.test`),
   the production MX inside the enclave with TLS terminating there, and the
   recovery domain's MTA-STS policy.
8. **Verification code derivation.** v1 (§10.1) keys the code with
   `k_code`, derived from `account_code` and registered sealed with the
   vault. Alternatives: a key from the owner passkey's PRF output, which
   lets the owner's device confirm that an alert came from the vault but
   which a recovering device that lost the passkey cannot compute; or a
   code computed from the attempt's public statement digest without any
   key, which every device can show but which the sending service and the
   user's mail provider can match to the on-chain attempt, linking the
   inbox to the account, and which whoever chooses a statement can steer.
9. **On-chain enrollment proof.** v1 checks the enrollment email in the
   wallet only (§5.4). A guardian constructor that verifies a proof of the
   enrollment email would make `C` verifiable by third parties, at the cost
   of a second circuit.
10. **Guardian deployment.** The wallet deploys each guardian directly from
    its submitter account and then checks the deployed wasm hash and
    `config()` (§5.4 step 4). Open: whether to deploy through a Nido factory
    instead (fixing the wasm hash and the address derivation on chain), and
    who pays on mainnet, where no friendbot funds the submitter.
11. **Wallet policy.** The rules of §9.3 are built in `recoverySpec` and
    tested (§9.3 lists the tests). They bind Nido's wallet only: the chain
    accepts any configuration the owner applies. The wallet sets the second
    alert channel only after the alert service has confirmed the contact
    with its Web Push subscription (§5.4, §10.3), and checks it again at
    runtime (§9.3 rule 2): this device's subscription and its last
    acknowledged probe without a prompt, the vault's view of every device
    with the passkey. The vault's view is as fresh as its last probes (30
    days apart by default, §10.6). Open: whether the wallet should read it on
    every open, at the cost of a passkey prompt.
12. **Address and domain bounds.** `ADDR_MAX = 124` and the 62-byte leaf
    domain cover the launch providers. Custom domains would need larger
    bounds, which change `C`'s packing and the leaf format (a new version).
13. **Custodians.** Who the three custodians are (at least one outside
    Nido), the protocol and key storage they run in production, and how
    they read the registry (its events, as the mocks do, or its contract
    state).
14. **Production enclave.** The binding to `/dev/nsm`, the vsock channel
    with TLS terminating inside the enclave, and a reproducible image build
    that publishes PCR0 to PCR2 are not built.
15. **Outages longer than RPC retention.** A watcher stopped for longer than
    the RPC's history (120,960 ledgers by default) loses events;
    reconciliation from controller state and the lag alarm are built
    (§10.2). Not built: a monitor outside the watcher that alarms when it
    stops polling (it reads `GET /v1/health`), and a choice of whether the
    email-plus-delay floor should exceed the longest tolerated outage.
16. **Accounts without an email guardian.** `k_code` comes from
    `account_code`, which such accounts do not have. Their alerts would need
    another key for the code, for example one kept in the recovery kit.
17. **What the host learns.** The host reads the chain state of every
    account that registers or changes a contact, so it learns which
    accounts do so and when, and outbound traffic timing shows which
    accounts have contacts. Whether to blur this (cover traffic, batched
    reads) is open.
18. **Failover duplicates.** Scaleway's API has no idempotency key, so a
    Lettermint request that was accepted but whose answer was lost can be
    delivered twice.
19. **Enclave-image registry governance.** Its signers and threshold, whether
    a signer outside Nido must be among the approvers, and how the signer
    set changes (today: deploying a new registry and pointing the
    custodians at it).
20. **Push probe visibility.** Each probe shows a notification that asks to
    be tapped (§10.6), because WebKit revokes subscriptions whose pushes show
    nothing, and because a tap is what shows a device still reaches its
    owner. How long subscriptions survive on Android Chrome and in an iOS
    home-screen web app, how many users tap the monthly check, and whether a
    tap-to-confirm notification teaches users to tap Nido notifications
    without reading them, are not measured; neither is the interval's
    trade-off between fewer notifications and finding an unreachable device
    sooner.
21. **Email votes to cancel.** An email vote to cancel an attempt is alerted
    on every channel (§10.2, `email_cancel_recorded`): under a guardian-only
    quorum of one, an inbox thief with the code can approve cancelling the
    owner's own attempts (`cancel_guardians`). Whether email should be
    allowed to cancel by default is open (question 3).
22. **A lower target ledger close time.** The windows of this design are
    close time and keep their length (§2 "Two clocks"); Perch's delay is a
    ledger count fixed in each recovery member. If validators lower
    `ledger_target_close_time_milliseconds`, an email-plus-delay member
    built at the old target lasts less than 7 days (at 4,000 ms, 5.6 days)
    until its owner rebuilds it, which the wallet then sizes at the new
    target (§9.3 rule 3). Not built: the wallet noticing a lower target
    and asking those owners to rebuild, and whether to leave a margin above
    the floor for that case.
23. **Provider sender authentication (A1b).** Unknown today for every launch
    provider: whether its submission path refuses two `From` fields or an
    address in the display name, and which `from` instance its signature
    then covers (a `From` naming several addresses does not reach a proof:
    the circuit refuses it, §4.5). Unknown for Outlook.com,
    iCloud and GMX/WEB.DE: whether a user can send as another existing
    mailbox of the domain. Unknown for iCloud and Yahoo: whether a deleted
    address is assigned again (Fastmail and GMX/WEB.DE document that they
    are; `account_code` covers it). A controlled submission test from test
    accounts would settle the first; it sends real mail through the
    providers, which this repository's mocks do not
    (`research/email-recovery/eval/parser/sender-authentication.md`).
25. **Keeping the contracts live.** The operator's keeper
    (`research/email-recovery/eval/network/keeper.mjs`) extends the email
    verifier, the key registry, the guardian's code and every enrolled
    account's guardian instance before they archive (§12, "Keeping the
    contracts live"). Open: who funds it on mainnet; whether the wallet
    extends an account's own entries when it opens, since Perch's account
    and controller are not Nido's to keep; and whether the keeper also
    extends the registry's tree paths and proposals (`renew_path`), which
    governance reads and votes do not.

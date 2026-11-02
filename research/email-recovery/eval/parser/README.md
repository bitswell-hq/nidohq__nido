# The circuit's header parsing: real mail and fuzzing

The soundness theorem (`EmailRecovery.soundness`, spec §11.3) takes the
circuit's reading of a header block as a parameter: the Lean model's
`Format` is an arbitrary function, so the theorem holds for any parser. Two
checks here test the Noir parser itself, independently of the mocks the
circuit was built against, and a review of public sources covers the
provider behaviour the theorem assumes:

1. **Differential testing on real mail.** Real DKIM-signed posts from launch
   providers, taken from public mailing-list archives with real provider
   keys, run through the circuit and through reference implementations.
2. **Grammar-based fuzzing.** Seeded header blocks around the boundaries of
   the From grammar (spec §4.5) and the DKIM-Signature tag list (§4.3),
   signed with a TEST-ONLY key, checked against an invariant.
3. **Sender authentication per provider** (assumption A1b):
   [sender-authentication.md](sender-authentication.md).

Everything below the method was **run** in this repository (on an 18-core
Apple M5 Max, macOS, Node 24.18.0, Python 3.14.4); the provider review in
part 3 was **read**, not tested.

## Method

### What runs through the circuit

The recovery circuit requires the Subject to be the recovery phrase followed
by 64 hex characters (spec §4.2), which no real post carries. The checks
therefore execute a TEST-ONLY harness, [`harness/src/main.nr`](harness/src/main.nr):
`email_recovery::dkim::verify_dkim_header` at the recovery circuit's bounds
(`HEADER_MAX` 1536, `DKIM_FIELD_MAX` 512, `DKIM_TAGS_MAX` 16, `ADDR_MAX`
124), built from the same library with Perch's pinned nargo, with exactly
one call removed: `subject::parse_subject`, the Subject value check. Every
other check runs unchanged: the header scan (including exactly one `from:`
and one `subject:` line), SHA-256 and RSA-2048, the From grammar, and the
DKIM-Signature tags with `d=` equal to the From domain. Instead of binding
the commitment, the Subject opening and the key tree, which a real post
cannot open, the harness returns the From address, the lowercase `d=` and
the key hash, and the hints the checks ran on. The hints (the From address's
position, length and `@` index, the DKIM-Signature tag starts, the `h=`
entries and the `t=` length) are unconstrained, so in a proof the prover
chooses them; the harness finds them with `find_hints`, as the honest
prover does, or takes them from the caller (hint mutation, below).

Each input is also executed against the committed recovery artifact
(`circuits/email-recovery/artifacts/recovery.json`) with placeholder public
inputs (every input in part 1, every 25th case in part 2). Where the harness
refuses, the artifact must refuse with the same assertion; where the harness
accepts, the artifact must refuse at a Subject assertion. Inputs are built
by the wallet's own encoder functions (`signedHeaderBlock`, `limbs`,
`barrettHint` from `@nidohq/email-recovery`; a modulus too short for the
Barrett hint gets a zero hint, which only unconstrained code reads, so the
circuit itself judges the key) and executed with noir_js `execute`, without
proving.

For each DKIM-Signature field of a message, aligned with the From domain or
not, the circuit runs on the signed octets the reference builds and, where
they differ, also on the ones the encoder builds, under every candidate key;
it accepts the signature if any run accepts.

### The reference

- **DKIM:** mailauth 8.0.4 in its strict mode (RFC 6376 tag-list syntax,
  required tags, `v=`, `i=`, `q=`, From signed) selects and canonicalizes
  the signed header fields; node:crypto checks the RSA signature over those
  octets. mailauth stops at a changed body before checking the signature,
  and an archived post's body often differs from what was signed, so the
  header signature is checked directly; the body is not part of the recovery
  proof (spec §4.4). For the same reason `l=` longer than the body, and the
  times `t=` and `x=` (§4.4), are not rejections.
- **From:** Python's standard-library RFC 5322 parser
  (`email.headerregistry`, [`lib/from_ref.py`](lib/from_ref.py)) reads the
  From field the signature covers; its single mailbox is the address the
  circuit's must equal. mailauth's own RFC 5322 From reader is recorded as a
  second reading.
- **The spec's profile** ([`lib/reference.mjs`](lib/reference.mjs),
  `profileViolation`): the rules spec §4.3, §4.5 and §6.3 add to a valid
  signature (RSA-2048 with exponent 65537, `v=1`, `a=rsa-sha256`, relaxed
  header canonicalization, `h=` naming from and subject, one signed From and
  Subject, the header, field and tag bounds, the §4.5 address and value
  shape, `d=` equal to the From domain, the 62-octet leaf domain), evaluated
  on the reference's own parse.

### Verdicts

| Verdict | Meaning |
| --- | --- |
| agree-accept | Both accept; the circuit binds the address Python reads and the lowercase `d=` |
| agree-refuse | Both refuse |
| soundness | The circuit accepts, and the reference DKIM verifier refuses the signature (kind `dkim`), or Python does not read exactly one mailbox equal to the circuit's address (kind `from`), or the domain differs (kind `domain`) |
| spec-deviation | The circuit accepts and binds the address Python reads, but a rule the spec states refuses it |
| completeness | The reference and the spec's rules accept; the circuit refuses |

## Part 1: real mail

### Corpus

[`build-corpus.mjs`](build-corpus.mjs) downloads the GNU Mailman mbox
archives named in [`corpus/sources.json`](corpus/sources.json)
(`https://lists.gnu.org/archive/mbox/<list>/<month>`, the archives
`packages/email-mocks/PROVIDERS.md` cites, at the 10-second pace their
robots.txt asks for) and keeps every post whose From domain is a launch
domain and that carries a DKIM-Signature field. Nothing from a message is
committed: [`corpus/manifest.json`](corpus/manifest.json) gives each post's
archive URL, its position in the mbox, the SHA-256 of its octets as stored,
its From domain and the `d=`/`s=` of its signatures, and the checks fetch
the posts again (cached under `target/`) and verify each hash. The
archive's LF line ends become CRLF, the wire form.

[`corpus/keys.json`](corpus/keys.json) holds every candidate public key for
each (`d=`, `s=`): the live DNS record where one is published, and every key
zkEmail's public DKIM key archive (<https://archive.zk.email>) observed for
that selector, each with its source and dates. The reference tries each
candidate and records which one verified.

The committed results quote no sender: [`results/differential.json`](results/differential.json)
masks every letter and digit of a quoted From value, keeping its structure
and domain; the unmasked rows stay under `target/`.

### Results

<!-- BEGIN GENERATED real-mail by report.mjs; do not edit -->
Corpus: 5,154 posts from 18 lists at https://lists.gnu.org/archive/mbox, months 2025-10, 2026-05, 2026-06, 2026-07, 2026-08, 2026-09, 2026-10 (manifest built 2026-11-02); 0 no longer served. 5,327 DKIM-Signature fields, 10,320 circuit executions (harness and recovery artifact), 380 s, Python 3.14.4.

| From domain | Posts | Signatures (aligned) | Reference accepts | Circuit accepts | Posts in agreement |
| --- | --- | --- | --- | --- | --- |
| fastmail.com | 11 | 22 (11) | 0 | 0 | 11 |
| gmail.com | 3,971 | 4,131 (3,971) | 3,558 | 3,558 | 3,971 |
| gmx.de | 225 | 226 (225) | 204 | 204 | 225 |
| gmx.net | 76 | 77 (76) | 59 | 59 | 76 |
| hotmail.com | 19 | 19 (19) | 12 | 12 | 19 |
| icloud.com | 40 | 40 (40) | 40 | 40 | 40 |
| outlook.com | 362 | 362 (362) | 361 | 361 | 362 |
| proton.me | 66 | 66 (66) | 62 | 62 | 66 |
| protonmail.com | 229 | 229 (229) | 221 | 221 | 229 |
| web.de | 134 | 134 (134) | 81 | 81 | 134 |
| yahoo.com | 21 | 21 (21) | 21 | 21 | 21 |
| **all** | 5,154 | 5,327 (5,154) | 4,619 | 4,619 | 5,154 |

Verdicts per signature: agree-accept 4,619, agree-refuse 708. Result: the circuit accepts exactly the signatures the reference accepts, and binds the address Python reads. The recovery artifact agreed with the harness on 5,327 of 5,327 signatures; the encoder's signed block differed from the reference's on 0; the verifying key came from the live DNS for 4,419 signatures and only from zkEmail's archive for 592. Python and mailauth read the From of every accepted signature the same way: yes.
<!-- END GENERATED real-mail -->

Why signatures are refused, by both sides:

<!-- BEGIN GENERATED real-mail-reasons by report.mjs; do not edit -->
| Why the reference refuses a signature | Signatures | Circuit refusal |
| --- | --- | --- |
| DKIM: the signature does not verify under any candidate key | 316 | `RSA: signature does not verify` (under every candidate key) |
| Spec 6.3: the signed data is N octets, above 1536 | 229 | `encoder: the signed header block is N octets; the circuit takes at most N` |
| Spec 4.3 rule 7: d= is not the From domain | 162 | `DKIM: d= must equal the From domain` |
| Spec 4.3 rule 6: the signed data has no single subject field | 1 | `header: exactly one signed Subject field is required` |
<!-- END GENERATED real-mail-reasons -->

Mismatches:

<!-- BEGIN GENERATED real-mail-mismatches by report.mjs; do not edit -->
None: no post in the corpus has a signature the circuit and the reference judge differently, and every accepted signature binds the address Python reads.
<!-- END GENERATED real-mail-mismatches -->

What the corpus does and does not cover:

- Every launch domain is present, but unevenly: most posts are Gmail's.
- Neither of Fastmail's two signatures (`d=fastmail.com` and
  `d=messagingengine.com`) verifies on any of its 11 posts under any key the
  DNS or zkEmail's archive holds; whether the list changed a signed field or
  the signing key is in neither source was not established. Fastmail is
  therefore tested on the refusing side only here, and on the accepting side
  by its mock (`circuits/email-recovery/README.md`).
- Of the signatures refused for the header bound, 197 have `References` or
  `In-Reply-To` as their longest signed field (replies in long threads); the
  others sign a long `Cc`, `Autocrypt`, `Face` or `Mail-Followup-To` field. A
  recovery email is a new message to one recipient (spec §4.1).
- Archived copies show what the list delivered, not what each provider's
  outbound path produced; posts whose signature no longer verifies test
  only refusals.

## Part 2: grammar-based fuzzing

[`lib/grammar.mjs`](lib/grammar.mjs) generates each case from a seed and its
index alone, so every case can be rerun by itself (`node fuzz.mjs --show
<index>`). A case starts from an ordinary message and applies one family of
mutations (or, in `mixed`, two to four):

| Family | Around |
| --- | --- |
| from-display | display names with `<`, `>`, quotes, commas, colons, semicolons, `@`, comments, encoded-words, an address, 8-bit octets, lengths up to 900 octets |
| from-address | local parts (dot-atom edges, quoted strings, specials, 8-bit) and domains (RFC 1123 label edges, 63- and 64-octet labels, literals, a trailing dot, case) |
| from-structure | bare and angle forms, comments after the address, lists, groups, routes, spaces inside the angle brackets, nested or extra brackets, folds |
| encoded-words | RFC 2047 words, well formed or not, carrying an address or angle brackets |
| folding | folds at whitespace in any field, in the From value and inside the tag list |
| duplicated-fields | a second From or Subject above or below, with `h=` naming it once or twice; the signature moved |
| field-names | case, whitespace before the colon, look-alike names, Sender and Reply-To |
| h-list | case, spaces, oversigning, missing names, substring look-alikes, empty entries |
| tag-list | order, duplicates, unknown and empty tags, tags without `=`, upper-case names, whitespace around `=` and `;` |
| tag-values | `v=`, `a=`, `c=`, `d=`, `i=`, `q=`, `l=` values at and past their grammar |
| lengths | the header, field, tag, address and domain bounds |
| octets | NUL, control and 8-bit octets in any field |

[`lib/sign.mjs`](lib/sign.mjs) signs each case with the mocks' TEST-ONLY
`gmail` key (2% of cases with the 1024-bit `weak` key): the message is
assembled with an empty `b=`, the reference selects and canonicalizes the
signed octets, and their RSA signature becomes `b=`. Where the reference
does not process the field at all, the encoder's octets are signed instead,
so the circuit still sees a valid signature and must refuse the field on
its own. The invariant checked on every signature: **if the circuit accepts,
the reference DKIM verifier accepts, Python reads exactly one mailbox, the
circuit's address is that mailbox, and the circuit's domain is the lowercase
`d=`.**

### Results

<!-- BEGIN GENERATED fuzz by report.mjs; do not edit -->
Seed `nido-email-recovery-parser-fuzz-v1`, cases 0 to 49,999: 50,000 cases, 49,779 DKIM-Signature fields (221 cases have none the reference recognizes), 51,814 circuit executions, 2123 s, Python 3.14.4. Signed over the reference's octets: 49,157; over the encoder's (fields the reference does not process): 617.

| Verdict | Signatures |
| --- | --- |
| agree-accept | 22,409 |
| agree-refuse | 23,967 |
| soundness | 2,692 |
| spec-deviation | 0 |
| completeness | 711 |

Invariant (circuit accepts ⇒ the reference DKIM verifier accepts, Python reads exactly the circuit's address, and the circuit's domain is the lowercase d=): **violated in 2692 signatures**. Every 25th case also ran the recovery artifact: 1,994 signatures, 0 disagreements with the harness. The encoder's signed block differed from the reference's on 267 signatures; the reference does not verify the signature: 266 (smallest case 237); the reference verifies the signature: 1 (smallest case 1114).
<!-- END GENERATED fuzz -->

By family:

<!-- BEGIN GENERATED fuzz-families by report.mjs; do not edit -->
| Family | Cases | Signatures | Circuit accepts | Reference and spec accept | Soundness | Spec deviation | Completeness |
| --- | --- | --- | --- | --- | --- | --- | --- |
| baseline | 1,053 | 1,053 | 1,030 | 1,030 | 0 | 0 | 0 |
| from-display | 4,897 | 4,897 | 2,070 | 2,070 | 0 | 0 | 0 |
| from-address | 4,069 | 4,069 | 802 | 802 | 0 | 0 | 0 |
| from-structure | 5,029 | 5,029 | 779 | 779 | 0 | 0 | 0 |
| encoded-words | 2,494 | 2,494 | 1,103 | 1,103 | 0 | 0 | 0 |
| folding | 3,008 | 3,008 | 2,141 | 2,141 | 0 | 0 | 0 |
| duplicated-fields | 4,032 | 4,032 | 2,487 | 2,487 | 0 | 0 | 0 |
| field-names | 1,943 | 1,809 | 1,039 | 1,039 | 0 | 0 | 0 |
| h-list | 3,947 | 3,947 | 2,265 | 2,265 | 0 | 0 | 0 |
| tag-list | 4,974 | 4,974 | 3,709 | 2,227 | 1,737 | 0 | 255 |
| tag-values | 4,104 | 4,104 | 2,214 | 1,878 | 723 | 0 | 387 |
| lengths | 2,966 | 2,966 | 2,350 | 2,350 | 0 | 0 | 0 |
| octets | 2,015 | 2,015 | 1,709 | 1,709 | 0 | 0 | 0 |
| mixed | 5,469 | 5,382 | 1,403 | 1,240 | 232 | 0 | 69 |
<!-- END GENERATED fuzz-families -->

The one block divergence on a signature the reference verifies is case
1114: a header line whose field name holds a tab (`From<TAB>x:`), which is
no field at all under RFC 5322 §2.2; mailauth joins it to the From field
above it, the encoder reads it as a field of its own.

Counterexamples to the invariant, by class (one example each; `node fuzz.mjs
--show <case>` prints the case):

<!-- BEGIN GENERATED fuzz-counterexamples by report.mjs; do not edit -->
| Kind | Class | Signatures | Example case | Example field | Python reads | Circuit binds |
| --- | --- | --- | --- | --- | --- | --- |
| dkim | signature syntax error | 1,826 | 12 | `DKIM-Signature:v=1; a=rsa-sha256; xf; c=relaxed/relaxed; d=icloud.com; s=fuzz; t=1793613600; h=from:to:subject` | — | `dn3u.zp4l8@icloud.com` |
| dkim | unsupported query method | 511 | 27 | `DKIM-Signature:v=1; a=rsa-sha256; c=relaxed/relaxed; q=d=protonmail.com; d=web.de; s=fuzz; t=1793613600; h=fro` | — | `0x97th.h1w0gm@web.de` |
| dkim | signature missing required tag | 234 | 613 | `DKIM-Signature:v=1; a=rsa-sha256; c=relaxed/relaxed; d=gmx.de; t=1793613600; h=from:to:subject:date:message-id` | — | `1y4c0d6r.imlw4d@gmx.de` |
| dkim | domain mismatch | 121 | 67 | `DKIM-Signature:v=1; a=rsa-sha256; i=@gmail.com; c=relaxed/relaxed; d=outlook.com; s=fuzz; t=1793613600; h=from` | — | `dln554wo.hs1z12l4@outlook.com` |
<!-- END GENERATED fuzz-counterexamples -->

Spec deviations (the circuit binds the address Python reads, but the spec
says it refuses the value):

<!-- BEGIN GENERATED fuzz-deviations by report.mjs; do not edit -->
None.
<!-- END GENERATED fuzz-deviations -->

Completeness gaps (the reference and the spec's rules accept, the circuit
refuses):

<!-- BEGIN GENERATED fuzz-gaps by report.mjs; do not edit -->
| Circuit refusal | Signatures | Example case | Example DKIM-Signature (start) |
| --- | --- | --- | --- |
| `DKIM: v= must be 1` | 228 | 459 | `DKIM-Signature:v=1 ; a=rsa-sha256; c=relaxed/relaxed; d=yahoo.com; s=fuzz; t=1793613600; h=from:to:subject:date:message-` |
| `DKIM: d= must equal the From domain` | 186 | 173 | `DKIM-Signature:v=1; a=rsa-sha256; c=relaxed/relaxed; d= icloud.com; s=fuzz; t=1793613600; h=from:to:subject:date:message` |
| `DKIM: a= must be rsa-sha256` | 139 | 761 | `DKIM-Signature:v=1; a=rsa-sha256 ; c=relaxed/relaxed; d=outlook.com; s=fuzz; t=1793613600; h=from:to:subject:date:messag` |
| `DKIM: header canonicalization must be relaxed` | 61 | 405 | `DKIM-Signature:v=1; a=rsa-sha256; c = relaxed/relaxed; d=web.de; s=fuzz; t=1793613600; h=from:to:subject:date:message-id` |
| `DKIM: b= must be empty in the signed field` | 53 | 610 | `DKIM-Signature:v=1; a=rsa-sha256; c=relaxed/relaxed; d=gmx.de; s=fuzz; t=1793613600; h=from:to:subject:date:message-id; ` |
| `DKIM: h= must list from` | 44 | 117 | `DKIM-Signature:v=1; a=rsa-sha256; c=relaxed/relaxed; d=hotmail.com; s=fuzz; t=1793613600; h ␍␊ = ␍␊ from:to:subject:date` |
<!-- END GENERATED fuzz-gaps -->

### Hint mutation

The runs above use the hints the honest prover finds. A dishonest prover
may supply any others, so `fuzz.mjs --mutate-hints` runs every signature
the circuit accepts on the honest hints again with each hint changed: each
From hint moved by -2 to +2, set to a random position and to `2^32 - 1`;
the address window moved with its end fixed and with its `@` fixed (which
would bind a suffix of the address); each present tag start moved by -2 to
+2 and set to a random position; the tag count and the `h=` and `t=` hints
moved by one. The invariant: the circuit refuses the mutated hint, or binds
the same address, domain and key hash as on the honest hints.

<!-- BEGIN GENERATED hint-mutation by report.mjs; do not edit -->
Seed `nido-email-recovery-parser-fuzz-v1`, cases 0 to 999: 997 DKIM-Signature fields, 490 accepted on the honest hints, 39,256 mutated hints, 40,255 circuit executions, 1218 s. Refused: 38,276; accepted with the same address, domain and key hash: 980; accepted with another binding: 0. Invariant (a mutated hint is refused or binds what the honest hints bind): **holds on every mutated hint**.

| Hint mutated | Runs | Refused | Same binding | Another binding |
| --- | --- | --- | --- | --- |
| `from.addr_start` | 2,939 | 2,939 | 0 | 0 |
| `from.addr_len` | 2,935 | 2,935 | 0 | 0 |
| `from.at_index` | 2,939 | 2,939 | 0 | 0 |
| `from window, end fixed` | 1,960 | 1,960 | 0 | 0 |
| `from window, @ fixed` | 1,960 | 1,960 | 0 | 0 |
| `tags.tag_starts` | 22,603 | 22,603 | 0 | 0 |
| `tags.tag_count` | 980 | 980 | 0 | 0 |
| `tags.h_from` | 980 | 980 | 0 | 0 |
| `tags.h_subject` | 980 | 980 | 0 | 0 |
| `tags.t_len` | 980 | 0 | 980 | 0 |
<!-- END GENERATED hint-mutation -->

The `t=` length is read only by `DkimSignature::timestamp`, which the
recovery circuit does not call, so changing it changes nothing.

## Findings

**The From display name (spec §4.5).** The circuit accepts a display name
only as `atext`, `.`, SP and closed quoted strings, with `\` only as a
quoted-pair inside one and no `<` or `>`, so it refuses From values whose
display name holds an unquoted `,`, `;`, `:`, `@`, `\` or parenthesis, or
an unbalanced `"`: values RFC 5322 readers read as an address list, a group,
another mailbox, or no mailbox. [`from-finding.mjs`](from-finding.mjs)
builds such values as full recovery emails (the real recovery Subject, a
commitment, a key-tree path) signed with the TEST-ONLY Yahoo key and executes
the committed recovery artifact; the first row is a plain display name for
comparison:

<!-- BEGIN GENERATED from-finding by report.mjs; do not edit -->
| Signed From value | Python reads | mailauth reads | Recovery artifact |
| --- | --- | --- | --- |
| `Ann Lee <t5w6.i9otz@yahoo.com>` | `["t5w6.i9otz@yahoo.com"]` | `["t5w6.i9otz@yahoo.com"]` (valid) | accepts, opens the commitment with `t5w6.i9otz@yahoo.com` |
| `b4ionwm6.ajw@yahoo.com, x <t5w6.i9otz@yahoo.com>` | `["b4ionwm6.ajw@yahoo.com","t5w6.i9otz@yahoo.com"]` | `["b4ionwm6.ajw@yahoo.com","t5w6.i9otz@yahoo.com"]` (valid) | refuses: `From: invalid display name` |
| `b4ionwm6.ajw@yahoo.com <t5w6.i9otz@yahoo.com>` | `["b4ionwm6.ajw@yahoo.com"]` (defects) | `["b4ionwm6.ajw@yahoo.com","t5w6.i9otz@yahoo.com"]` (lax) | refuses: `From: invalid display name` |
| `"q97" b4ionwm6.ajw@yahoo.com <t5w6.i9otz@yahoo.com>` | `["\"q97 b4ionwm6.ajw\"@yahoo.com"]` (defects) | `[]` (invalid) | refuses: `From: invalid display name` |
| `"x <t5w6.i9otz@yahoo.com>` | `["\"x <t5w6.i9otz@yahoo.com>\""]` (defects) | `[]` (invalid) | refuses: `From: invalid display name` |
<!-- END GENERATED from-finding -->

The second row is a valid RFC 5322 address list. A provider that
authenticates only the first address of such a From (in 2020, Yahoo's and
iCloud's submission paths accepted several addresses and checked only the
first, [sender-authentication.md](sender-authentication.md)) would sign
mail for the attacker's account that names the victim's address
last; the circuit refuses it at the display-name check. In part 2 no From
class remains among the counterexamples, and no spec deviation: every From
value the circuit accepts, Python reads as exactly the mailbox it binds.
Among the values both refuse are 600 that Python reads as one mailbox but
whose display name the grammar excludes; of the 596 that nothing else
refuses, 498 hold a comment and 98 an RFC 2047 encoded-word with an `@`,
which a reader that decodes before parsing would read as an address. In
part 1 no real post's From is outside the grammar: of the signatures the
circuit accepts, every display name is a quoted string, encoded-words, or
plain atoms.

**Tag-list rules (stated in spec §4.3).** The
circuit checks `v=`, `a=`, `c=`, `d=`, `h=` and `b=` and the boundaries of
every tag, but accepts a field RFC 6376 tells verifiers to ignore for a
defect in a tag it does not read: an empty tag-spec or a tag without `=`, a
missing or duplicate `s=`, a missing `bh=`, a non-numeric `l=`, `i=` outside
`d=`, `q=` without `dns/txt`. Only the holder of the signing key writes that field, so under
A1a nobody else can produce one. It also refuses whitespace around `=` or
before `;` in `v=`, `a=`, `c=`, `d=` and `b=`, and between `h` and `=`,
which RFC 6376 §3.2 allows; whitespace around the entries of `h=` is
accepted. In part 1 such whitespace occurs only in Fastmail's `h=` (a fold
after `=`, accepted) and in `d= messagingengine.com` (Fastmail's second
signature, refused for its `d=` in any case). Both are counted above as
`dkim` counterexamples and completeness gaps.

**Sender authentication (open, §13 question 23).** Which `from` instance and
which address each provider authenticates on submission today is unknown
for every launch provider; [sender-authentication.md](sender-authentication.md)
gives the evidence per provider and what would settle each unknown.

## Running it

| What | Command | Time here |
| --- | --- | --- |
| Everything, rewriting `results/` and these tables | `just email-recovery-parser-check` ([`check.sh`](check.sh)) | about an hour (part 1 about nine minutes, part 2 about forty, hint mutation about twenty), plus the archive downloads on a first run |
| The CI subset: the first 10 posts per launch domain and the first 2,000 cases, which must reproduce `results/` exactly, and hint mutation on the first 50 cases, which must hold its invariant | `research/email-recovery/eval/parser/check.sh --ci` ([`compare-results.mjs`](compare-results.mjs)) | a few minutes |
| Hint mutation alone | `node research/email-recovery/eval/parser/fuzz.mjs --mutate-hints --cases 1000` | about 20 minutes (1,218 s on 17 workers, load average above 40) |
| One fuzz case, printed | `node research/email-recovery/eval/parser/fuzz.mjs --show <index>` | seconds |
| Rebuilding the corpus manifest and key list | `node research/email-recovery/eval/parser/build-corpus.mjs` | about 25 minutes, at the archive's pace |

Prerequisites: `git submodule update --init`, `npm ci`, Python 3 (standard
library only). `check.sh` installs Perch's pinned nargo into
`target/zk-toolchain` and compiles the harness. CI runs the subset in
`.github/workflows/email-recovery-parser.yml`, with Python 3.14, the
version the results were made with.

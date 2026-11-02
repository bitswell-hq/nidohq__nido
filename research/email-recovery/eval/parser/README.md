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
the key hash.

Each input is also executed against the committed recovery artifact
(`circuits/email-recovery/artifacts/recovery.json`) with placeholder public
inputs (every input in part 1, every 25th case in part 2). Where the harness
refuses, the artifact must refuse with the same assertion; where the harness
accepts, the artifact must refuse at a Subject assertion. Inputs are built
by the wallet's own encoder functions (`signedHeaderBlock`, `limbs`,
`barrettHint` from `@nidohq/email-recovery`) and executed with noir_js
`execute`, without proving.

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
Corpus: 5,154 posts from 18 lists at https://lists.gnu.org/archive/mbox, months 2025-10, 2026-05, 2026-06, 2026-07, 2026-08, 2026-09, 2026-10 (manifest built 2026-11-02); 0 no longer served. 5,327 DKIM-Signature fields, 10,320 circuit executions (harness and recovery artifact), 512 s, Python 3.14.4.

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

Verdicts per signature: posts NaN, codes NaN. Result: the circuit accepts exactly the signatures the reference accepts, and binds the address Python reads. The recovery artifact agreed with the harness on 5,327 of 5,327 signatures; the encoder's signed block differed from the reference's on 0; the verifying key came from the live DNS for 4,419 signatures and only from zkEmail's archive for 592. Python and mailauth read the From of every accepted signature the same way: yes.
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
Seed `nido-email-recovery-parser-fuzz-v1`, cases 0 to 49,999: 50,000 cases, 49,779 DKIM-Signature fields (221 cases have none the reference recognizes), 51,814 circuit executions, 2685 s, Python 3.14.4. Signed over the reference's octets: 49,157; over the encoder's (fields the reference does not process): 617.

| Verdict | Signatures |
| --- | --- |
| agree-accept | 23,002 |
| agree-refuse | 20,619 |
| soundness | 5,193 |
| spec-deviation | 251 |
| completeness | 714 |

Invariant (circuit accepts ⇒ the reference DKIM verifier accepts, Python reads exactly the circuit's address, and the circuit's domain is the lowercase d=): **violated in 5193 signatures**. Every 25th case also ran the recovery artifact: 1,994 signatures, 0 disagreements with the harness. The encoder's signed block differed from the reference's on 267 signatures, 1 of them valid under the key by the reference.
<!-- END GENERATED fuzz -->

By family:

<!-- BEGIN GENERATED fuzz-families by report.mjs; do not edit -->
| Family | Cases | Signatures | Circuit accepts | Reference and spec accept | Soundness | Spec deviation | Completeness |
| --- | --- | --- | --- | --- | --- | --- | --- |
| baseline | 1,053 | 1,053 | 1,030 | 1,030 | 0 | 0 | 0 |
| from-display | 4,897 | 4,897 | 4,034 | 2,429 | 1,458 | 147 | 0 |
| from-address | 4,069 | 4,069 | 802 | 802 | 0 | 0 | 0 |
| from-structure | 5,029 | 5,029 | 1,193 | 817 | 352 | 24 | 0 |
| encoded-words | 2,494 | 2,494 | 1,144 | 1,144 | 0 | 0 | 0 |
| folding | 3,008 | 3,008 | 2,711 | 2,237 | 422 | 52 | 0 |
| duplicated-fields | 4,032 | 4,032 | 2,487 | 2,487 | 0 | 0 | 0 |
| field-names | 1,943 | 1,809 | 1,039 | 1,039 | 0 | 0 | 0 |
| h-list | 3,947 | 3,947 | 2,265 | 2,265 | 0 | 0 | 0 |
| tag-list | 4,974 | 4,974 | 3,709 | 2,227 | 1,737 | 0 | 255 |
| tag-values | 4,104 | 4,104 | 2,214 | 1,878 | 723 | 0 | 387 |
| lengths | 2,966 | 2,966 | 2,350 | 2,350 | 0 | 0 | 0 |
| octets | 2,015 | 2,015 | 1,709 | 1,709 | 0 | 0 | 0 |
| mixed | 5,469 | 5,382 | 1,759 | 1,302 | 501 | 28 | 72 |
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
| dkim | signature syntax error | 1,856 | 12 | `DKIM-Signature:v=1; a=rsa-sha256; xf; c=relaxed/relaxed; d=icloud.com; s=fuzz; t=1793613600; h=from:to:subject` | — | `dn3u.zp4l8@icloud.com` |
| from | unquoted `@` (an address in the display name) | 1,181 | 14 | `from:jx90 @ ky3p <w8utgn2.3mdly87k@icloud.com>` | `["jx90@ky3p"]` | `w8utgn2.3mdly87k@icloud.com` |
| dkim | unsupported query method | 517 | 27 | `DKIM-Signature:v=1; a=rsa-sha256; c=relaxed/relaxed; q=d=protonmail.com; d=web.de; s=fuzz; t=1793613600; h=fro` | — | `0x97th.h1w0gm@web.de` |
| from | unbalanced `"` in the display name | 507 | 0 | `from:"ij8 <wh1gv.eajo0z@fastmail.com>` | `["\"ij8 <wh1gv.eajo0z@fastmail.com>\""]` | `wh1gv.eajo0z@fastmail.com` |
| from | unquoted `\` | 271 | 212 | `from:rsm\9z7 <y82wvin.ak65uxjq@gmail.com>` | `["\"rsm\\\\9z7\""]` | `y82wvin.ak65uxjq@gmail.com` |
| from | unquoted `,` (an address list) | 255 | 51 | `from:myo, odv4 <yoq1xwj1.4qrc@protonmail.com>` | `["myo","yoq1xwj1.4qrc@protonmail.com"]` | `yoq1xwj1.4qrc@protonmail.com` |
| from | unquoted `;` | 246 | 33 | `from:mp2d; okdr <45fx.1wzle@hotmail.com>` | `["mp2d"]` | `45fx.1wzle@hotmail.com` |
| dkim | signature missing required tag | 237 | 613 | `DKIM-Signature:v=1; a=rsa-sha256; c=relaxed/relaxed; d=gmx.de; t=1793613600; h=from:to:subject:date:message-id` | — | `1y4c0d6r.imlw4d@gmx.de` |
| dkim | domain mismatch | 123 | 67 | `DKIM-Signature:v=1; a=rsa-sha256; i=@gmail.com; c=relaxed/relaxed; d=outlook.com; s=fuzz; t=1793613600; h=from` | — | `dln554wo.hs1z12l4@outlook.com` |
<!-- END GENERATED fuzz-counterexamples -->

Spec deviations (the circuit binds the address Python reads, but the spec
says it refuses the value):

<!-- BEGIN GENERATED fuzz-deviations by report.mjs; do not edit -->
| Spec rule the circuit does not apply | Signatures | Example case | Signed From line |
| --- | --- | --- | --- |
| 4.5: From names N mailboxes (N groups) | 251 | 1 | `From: 96yf: 6uxg <7dil3.m46qk@icloud.com>` |
<!-- END GENERATED fuzz-deviations -->

Completeness gaps (the reference and the spec's rules accept, the circuit
refuses):

<!-- BEGIN GENERATED fuzz-gaps by report.mjs; do not edit -->
| Circuit refusal | Signatures | Example case | Example DKIM-Signature (start) |
| --- | --- | --- | --- |
| `DKIM: v= must be 1` | 230 | 459 | `DKIM-Signature:v=1 ; a=rsa-sha256; c=relaxed/relaxed; d=yahoo.com; s=fuzz; t=1793613600; h=from:to:subject:date:message-` |
| `DKIM: d= must equal the From domain` | 186 | 173 | `DKIM-Signature:v=1; a=rsa-sha256; c=relaxed/relaxed; d= icloud.com; s=fuzz; t=1793613600; h=from:to:subject:date:message` |
| `DKIM: a= must be rsa-sha256` | 140 | 761 | `DKIM-Signature:v=1; a=rsa-sha256 ; c=relaxed/relaxed; d=outlook.com; s=fuzz; t=1793613600; h=from:to:subject:date:messag` |
| `DKIM: header canonicalization must be relaxed` | 61 | 405 | `DKIM-Signature:v=1; a=rsa-sha256; c = relaxed/relaxed; d=web.de; s=fuzz; t=1793613600; h=from:to:subject:date:message-id` |
| `DKIM: b= must be empty in the signed field` | 53 | 610 | `DKIM-Signature:v=1; a=rsa-sha256; c=relaxed/relaxed; d=gmx.de; s=fuzz; t=1793613600; h=from:to:subject:date:message-id; ` |
| `DKIM: h= must list from` | 44 | 117 | `DKIM-Signature:v=1; a=rsa-sha256; c=relaxed/relaxed; d=hotmail.com; s=fuzz; t=1793613600; h ␍␊ = ␍␊ from:to:subject:date` |
<!-- END GENERATED fuzz-gaps -->

## Findings

**The From display name (open, spec §13 question 23).** Spec §4.5 allows any
printable ASCII but `<` and `>` in the display name, so the circuit accepts
From values whose display name holds an unquoted `,`, `;`, `:`, `@` or `\`,
or an unbalanced `"`, and binds the angle-addr that ends the field. RFC 5322
readers read the same value as an address list, a group, another mailbox, or
no mailbox. [`from-finding.mjs`](from-finding.mjs) builds each of these as a
full recovery email (the real recovery Subject, a commitment, a key-tree
path) signed with the TEST-ONLY Yahoo key and executes the committed
recovery artifact:

<!-- BEGIN GENERATED from-finding by report.mjs; do not edit -->
| Signed From value | Python reads | mailauth reads | Recovery artifact |
| --- | --- | --- | --- |
| `Ann Lee <t5w6.i9otz@yahoo.com>` | `["t5w6.i9otz@yahoo.com"]` | `["t5w6.i9otz@yahoo.com"]` (valid) | accepts, opens the commitment with `t5w6.i9otz@yahoo.com` |
| `b4ionwm6.ajw@yahoo.com, x <t5w6.i9otz@yahoo.com>` | `["b4ionwm6.ajw@yahoo.com","t5w6.i9otz@yahoo.com"]` | `["b4ionwm6.ajw@yahoo.com","t5w6.i9otz@yahoo.com"]` (valid) | accepts, opens the commitment with `t5w6.i9otz@yahoo.com` |
| `b4ionwm6.ajw@yahoo.com <t5w6.i9otz@yahoo.com>` | `["b4ionwm6.ajw@yahoo.com"]` (defects) | `["b4ionwm6.ajw@yahoo.com","t5w6.i9otz@yahoo.com"]` (lax) | accepts, opens the commitment with `t5w6.i9otz@yahoo.com` |
| `"q97" b4ionwm6.ajw@yahoo.com <t5w6.i9otz@yahoo.com>` | `["\"q97 b4ionwm6.ajw\"@yahoo.com"]` (defects) | `[]` (invalid) | accepts, opens the commitment with `t5w6.i9otz@yahoo.com` |
| `"x <t5w6.i9otz@yahoo.com>` | `["\"x <t5w6.i9otz@yahoo.com>\""]` (defects) | `[]` (invalid) | accepts, opens the commitment with `t5w6.i9otz@yahoo.com` |
<!-- END GENERATED from-finding -->

The second row is a valid RFC 5322 address list, which §4.5 says is
refused. Whether the difference can be used depends on which address a
provider authenticates when a user submits such a From (A1b, condition 1):
in 2020, Yahoo's and iCloud's submission paths accepted several addresses in
`From` and checked only the first
([sender-authentication.md](sender-authentication.md)). A forger would also
need the victim's `account_code` to open the commitment. No real post in
part 1 has such a display name: of the signatures the circuit accepts, every
display name is a quoted string, encoded-words, or plain atoms. Spec §4.5
specifies the restriction that closes it (outside balanced quoted strings
only `atext`, `.` and WSP; `\` only as a quoted-pair inside one); the circuit
is not yet built with it. After that change, `just gen-email-proofs` and
`just email-recovery-parser-check` rerun every check here against the new
circuit (the harness compiles from `circuits/email-recovery/lib`, and
`PARSER_CHECK_ARTIFACT` selects another recovery artifact).

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

**Sender authentication (open, §13 question 24).** Which `from` instance and
which address each provider authenticates on submission today is unknown
for every launch provider; [sender-authentication.md](sender-authentication.md)
gives the evidence per provider and what would settle each unknown.

## Running it

| What | Command | Time here |
| --- | --- | --- |
| Everything, rewriting `results/` and these tables | `just email-recovery-parser-check` ([`check.sh`](check.sh)) | about an hour (part 1 ten minutes, part 2 fifty), plus the archive downloads on a first run |
| The CI subset: the first 10 posts per launch domain and the first 2,000 cases, which must reproduce `results/` exactly | `research/email-recovery/eval/parser/check.sh --ci` ([`compare-results.mjs`](compare-results.mjs)) | a few minutes |
| One fuzz case, printed | `node research/email-recovery/eval/parser/fuzz.mjs --show <index>` | seconds |
| Rebuilding the corpus manifest and key list | `node research/email-recovery/eval/parser/build-corpus.mjs` | about 25 minutes, at the archive's pace |

Prerequisites: `git submodule update --init`, `npm ci`, Python 3 (standard
library only). `check.sh` installs Perch's pinned nargo into
`target/zk-toolchain` and compiles the harness. CI runs the subset in
`.github/workflows/email-recovery-parser.yml`, with Python 3.14, the
version the results were made with.

# Evaluation: the email factor on a network

This directory evaluates email recovery as built in this repository
(`docs/email-recovery/spec.md`): an attack suite on a local Stellar network,
the email-recovery contracts on Stellar testnet with one complete
email-factor recovery, the on-chain cost of an email vote on the test host,
on the local network and on testnet, and the time and memory of proving a
recovery email natively, in Node and in a browser. Every table below is
generated from a file in `results/` (or from `browser-prover.json` and
`onchain.md`), and every file there is written by one of the commands under
[Running it](#running-it); figures quoted in the prose come from those
tables or from spec §12.

The four properties the scenarios exercise are those of spec §11.2:
**1** soundness of the email factor, **2** privacy, **3** replay and
front-running resistance, **4** one-factor safety.

## Running it

| What | Command | Writes |
| --- | --- | --- |
| Attack suite (local network and test host) | `just email-recovery-attacks` (`network/run-attacks.sh`) | `results/attacks-local.json`, `results/attacks-test-host.jsonl`, the tables below |
| Proving on this machine | `just email-recovery-proving` (`proving/measure.sh`) | `results/proving.json`, the proving table |
| Browser rows of the proving table | `node research/email-recovery/eval/measure-browser.mjs --runs 5` after `npx astro build --root packages/frontend` | `browser-prover.json`, `browser-prover.md` |
| Benchmark page for a phone | `just email-recovery-bench-phone` (`phone/build.mjs`, `phone/serve.mjs`); `node research/email-recovery/eval/phone/check.mjs` runs the build in headless Chrome | `target/email-bench-phone/`, served on the local network |
| Testnet deployment and recovery | `research/email-recovery/eval/testnet/run.sh` | `results/testnet.json`, `DEPLOYED.md` |
| Tables | `node research/email-recovery/eval/report.mjs` | this file |

Prerequisites: Docker, the Stellar CLI, `git submodule update --init`,
`just perch-infra`, `just build-contracts`, `npm ci` (which builds the npm
packages), and for the browser rows Playwright's Chromium and
`chrome-devtools-axi`. The attack runner first checks that `node_modules`
matches `package-lock.json` (`network/lib/preflight.mjs`) and names the
packages that differ; each run starts its own quickstart container on a free
port, so two runs on one machine do not stop each other's network.

An expert walkthrough of the enrollment and recovery pages, with the issues
it found and which were fixed, is [`walkthrough.md`](walkthrough.md). It is
not a user study.

## The attack suite

### Method

`network/attacks.mjs` runs under `node:test` against `stellar/quickstart
--local` (pinned by digest in `network/run-attacks.sh`). Everything on the
network is deployed from wasm by the suite itself (`network/lib/stack.mjs`):

- Perch's stack as a Nido account uses it (the local network's stateless
  deployer, Perch's doc compiler, interpreter, WebAuthn verifier, recovery
  controller, ZK pool and adapter, and the Perch account built for that
  deployer) and Nido's factory, as the email end-to-end test deploys them
  (`tests/support/emailLocalStack.mjs`);
- Nido's email verifier, the email guardian's wasm (each account deploys
  its own instance), and a DKIM key registry governed as spec §7.6 proposes:
  five members, threshold 3, revocation threshold 2, three DNS attesters
  (the TEST-ONLY attester mock, `crates/dns-attestation-mock`), attestation
  threshold 2, a 17,280-ledger grace period, the launch allowlist. Every
  launch domain's TEST-ONLY key is proposed, approved by three members and
  attested live in DNS by two attesters, so each addition waits in its
  72-hour timelock for the whole run;
- for the alert path, the alert service with its vault in its own process,
  three custodian mocks, the Lettermint, Scaleway and Web Push mocks
  (`network/lib/alerts.mjs`); its host reads the controller (`chainReads`)
  for email votes and reconciliation, as a deployment's would.

Each account is enrolled as the wallet enrolls one (spec §5.4): minted by
the factory with an owner passkey (a TEST-ONLY P-256 key behind the WebAuthn
authenticator mock), its email guardian deployed with the commitment `C` and
a 30-day key pin over its provider's key, and a document applied by the
owner's passkey whose recovery member lists the guardian, built by the
wallet's own `recoverySpec` so the wallet rules of spec §9.3 apply. Helpers
are funded Stellar accounts. Recovery emails are signed by the provider
mocks (`@nidohq/email-mocks`, each launch provider's header layout and
DKIM-Signature format) for the statement Perch's controller builds for the
live attempt; the wallet's encoder (`encodeRecoveryEmail`) prepares the
witness, noir_js solves it against the committed circuit artifact, and bb.js
0.87.0 proves it in Node. Every approval goes on chain as the wallet sends
it: the email approval in the guardian's authorization entry,
`submit_guardian` simulated with that entry enforced and then sent.

A scenario's outcome is what the network answered: accepted, or refused
with a contract error that the suite decodes to the contract that raised it
and its error enum (`network/lib/layers.mjs`: the guardian's `__check_auth`
check numbers of spec §8.3, the registry's and Perch's error enums). A
circuit refusal is noir_js's failed assertion on the attacker's strongest
witness (`network/lib/forge.mjs`: the signature a standard DKIM verifier
accepts if any, the octets it covers, the claimed account's accepted key
tree if the key is in it or a tree planted with the key otherwise, and the
claimed account's real commitment and statement digest). Where a forged
email still yields a valid witness (a key no tree the guardian accepts
holds, a guessed account code), the suite proves it and submits the proof,
so the refusal shown is the chain's.

**The alert path, phishing and repeated attempts.** These rows run the
mechanisms the email-plus-delay profile relies on (spec §11.4), not human
behaviour:

- *Compromised inbox.* The inbox thief holds the inbox and the account code
  and deletes every email sent to that inbox. The worst setup the wallet
  allows sends alerts to that inbox itself, so the suite counts an email as
  reaching the owner only when it goes to another address
  (`Alerts.reaching`); the push to the passkey device does. The owner's
  cancellation is a call the suite makes: the row shows that the mechanism
  succeeds within the delay, not that a person reacts. With two of two
  helpers the email vote leaves the attempt collecting, and the suite checks
  the alert the service sends for it.
- *Alert path.* A watcher outage longer than the RPC's event retention is
  modelled by a host that restarts reading at the current ledger with a
  fresh state file, so it never reads the attempt's events; only
  reconciliation from the controller can find them. A lapsed push is a
  subscription the push mock expires (it then answers 404, RFC 8030 §7.3).
- *Phishing.* The phisher opens a lost-key attempt for its own key, as the
  real recovery page would on its device, holds the victim's account code,
  and the victim's inbox sends the Subject the phisher shows. Where nobody
  can cancel, the account `S2` is enrolled outside the wallet's policy with a
  20-ledger delay so the delay elapses within the run (the wallet requires
  120,960 ledgers; the chain accepts any configuration).
- *Repeated attempts.* A funded stranger opens ten attempts on one account;
  the row counts what reaches the owner and what the controller lists.

**The chain's view.** `privacy-no-address-on-chain` is a sanity check behind
the privacy property, not evidence of hiding: it searches every
transaction's envelope, result and metadata, decoded and as base64, for each
inbox's address (raw, lower and upper case, hex, base64), its packed 31-byte
limbs as field words, its account code, and its pin's salt leaf.

Three registry scenarios need a registry timelock or grace period to have
elapsed (51,840, 120,960 and 17,280 ledgers). A local network closes about
one ledger a second, so they run on the integration-test host instead: the
registry's production wasm, its real timelocks and grace, the ledger
advanced, a real proof in every approval
(`crates/integration-tests/tests/it/email_guardian.rs`, `registry_*`; their
rows say "test host").

**In CI.** The local-network suite runs in its own workflow
(`.github/workflows/email-recovery-attacks.yml`) on pull requests and pushes
that touch what it exercises; on a GitHub-hosted Ubuntu runner it takes
about 26 minutes, beside the other workflows rather than after them. The
test-host scenarios run in the Tests workflow's `cargo test --workspace`,
and that workflow re-proves their fixtures.

### Results

<!-- BEGIN GENERATED attacks by report.mjs; do not edit -->
Local network: `stellar/quickstart --local` (stellar/quickstart@sha256:487fe637ba48c972d5be0ed8965f8df1dcbc3e8e1ee53d24d915b25b6f2b6d99), protocol 28, Stellar RPC 29.0.1 with captive core v29.0.0; run of 2026-11-02 05:12 UTC, 11 minutes, 213 transactions.
Test host: 3 rows from `crates/integration-tests/tests/it/email_guardian.rs` (`registry_*`).

| Class | Scenario | Expected | Observed | Refusing layer | Test | Property | Where |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Forged emails | forged-unsigned-or-duplicated-headers: a second, unsigned From or Subject above or below the signed one, at every provider format; h= without From | refused: 29 of 29 | refused: 29 of 29 | circuit | `attacks.mjs` forged-emails-circuit | 1 | local |
| Forged emails | forged-display-name-spoofing: the victim address in the display name, a comment, a quoted local part, a fold | refused: 11 of 11 | refused: 11 of 11 | circuit | `attacks.mjs` forged-emails-circuit | 1 | local |
| Forged emails | forged-misaligned-d: a signature by another domain, alone or under a forged one for the claimed domain | refused: 3 of 3 | refused: 3 of 3 | circuit | `attacks.mjs` forged-emails-circuit | 1 | local |
| Forged emails | forged-weak-key: an aligned signature under a 1024-bit key | refused: 1 of 1 | refused: 1 of 1 | circuit | `attacks.mjs` forged-emails-circuit | 1 | local |
| Forged emails | forged-signature-plus-modulus: b= is σ + N | refused: 1 of 1 | refused: 1 of 1 | circuit | `attacks.mjs` forged-emails-circuit | 1 | local |
| Forged emails | forged-body-and-length: l= with appended text; the value only in the body | refused: 2 of 2 | refused: 2 of 2 | circuit | `attacks.mjs` forged-emails-circuit | 1 | local |
| Forged emails | forged-bad-signature: the provider's own email with one character of b= changed | refused: RSA: signature does not verify | refused: RSA: signature does not verify | circuit | `attacks.mjs` forged-bad-signature | 1 | local |
| Forged emails | forged-wrong-key: a real proof under a key no registry or pin holds | refused: UnknownRoot | refused: UnknownRoot | guardian check 11 | `attacks.mjs` forged-wrong-key | 1 | local |
| Forged emails | forged-weak-key-registry: a registry addition of a 1024-bit key | refused: KeyNotRsa2048 | refused: KeyNotRsa2048 | registry | `attacks.mjs` forged-weak-key-registry | 1 | local |
| Forged emails | forged-misaligned-d-registry: a registry addition for Google's shared Workspace signing domain | refused: DomainNotAllowed | refused: DomainNotAllowed | registry | `attacks.mjs` forged-misaligned-d-registry | 1 | local |
| Forged emails | forged-wrong-body-hash: bh= of another body: counts one vote, as the provider signed the header block | accepted | accepted | — | `attacks.mjs` forged-wrong-body-hash | 1 | local |
| Replayed emails and proofs | replay-same-attempt-twice: The first submission counted one vote; the same approval in a fresh authorization entry is refused. | refused: AlreadyCounted | refused: AlreadyCounted | Perch controller | `attacks.mjs` replay-same-attempt-twice | 3 | local |
| Replayed emails and proofs | replay-another-attempt: a1's approval with its own statement, in a2's context | refused: DigestMismatch | refused: DigestMismatch | guardian check 2 | `attacks.mjs` replay-another-attempt | 3 | local |
| Replayed emails and proofs | replay-another-attempt-spliced: a2's statement with a1's proof | refused: ProofRejected | refused: ProofRejected | guardian check 12 | `attacks.mjs` replay-another-attempt | 3 | local |
| Replayed emails and proofs | replay-another-account: A's approval through B's guardian (same address, B's own account code) | refused: DigestMismatch | refused: DigestMismatch | guardian check 2 | `attacks.mjs` replay-another-account | 3 | local |
| Replayed emails and proofs | replay-another-account-spliced: B's statement with A's proof and key root: A's root is A's own salted pin, which B's guardian does not accept | refused: UnknownRoot | refused: UnknownRoot | guardian check 11 | `attacks.mjs` replay-another-account | 3 | local |
| Replayed emails and proofs | replay-another-account-rooted: B's statement and B's pin root with A's proof | refused: ProofRejected | refused: ProofRejected | guardian check 12 | `attacks.mjs` replay-another-account | 3 | local |
| Replayed emails and proofs | replay-another-account-guardian: A's guardian named for B's attempt | refused: NotAGuardian | refused: NotAGuardian | Perch controller | `attacks.mjs` replay-another-account | 3 | local |
| Replayed emails and proofs | replay-another-network: an approval of the statement with the testnet network id | refused: DigestMismatch | refused: DigestMismatch | guardian check 2 | `attacks.mjs` replay-another-network | 3 | local |
| Replayed emails and proofs | replay-another-network-spliced: this network's statement with that proof | refused: ProofRejected | refused: ProofRejected | guardian check 12 | `attacks.mjs` replay-another-network | 3 | local |
| Replayed emails and proofs | replay-another-controller: A's approval, asked for by a contract that is not A's controller | refused: UnexpectedContext | refused: UnexpectedContext | guardian check 1 | `attacks.mjs` replay-another-controller | 3 | local |
| Replayed emails and proofs | replay-expired-statement: proved before, submitted after the evidence deadline (ledger 244, the statement's valid_until_ledger) | refused: AttemptNotLive | refused: AttemptNotLive | Perch controller | `attacks.mjs` replay-expired-statement | 3 | local |
| Replayed emails and proofs | replay-email-circuit: an honest email presented for another statement of A, and for B | refused: 2 of 2 | refused: 2 of 2 | circuit | `attacks.mjs` forged-emails-circuit | 1 | local |
| Wrong account or new key in the statement | statement-other-new-key: the owner's approval (owner's new key) presented for the attacker's attempt (attacker's key) | refused: DigestMismatch | refused: DigestMismatch | guardian check 2 | `attacks.mjs` statement-other-new-key | 1 | local |
| Wrong account or new key in the statement | statement-other-new-key-spliced: the attacker's statement with the owner's proof | refused: ProofRejected | refused: ProofRejected | guardian check 12 | `attacks.mjs` statement-other-new-key | 1 | local |
| Wrong account or new key in the statement | statement-other-account: B's approval presented to A's guardian for A's attempt | refused: DigestMismatch | refused: DigestMismatch | guardian check 2 | `attacks.mjs` statement-other-account | 1 | local |
| Wrong account or new key in the statement | statement-other-account-spliced: A's statement with B's proof and key root: B's salted pin root, which A's guardian does not accept | refused: UnknownRoot | refused: UnknownRoot | guardian check 11 | `attacks.mjs` statement-other-account | 1 | local |
| Wrong account or new key in the statement | statement-other-account-rooted: A's statement and A's pin root with B's proof (another commitment) | refused: ProofRejected | refused: ProofRejected | guardian check 12 | `attacks.mjs` statement-other-account | 1 | local |
| Stale or malicious registry keys | registry-planted-key-timelock: not seen in DNS: the 72-hour path is closed, eligible at ledger 121281 (approved at 321, +120,960) | refused: TimelockActive | refused: TimelockActive | registry | `attacks.mjs` registry-planted-key-in-timelock | 1 | local |
| Stale or malicious registry keys | registry-planted-key-proof: a real proof against the root the planted addition would produce, during its timelock | refused: UnknownRoot | refused: UnknownRoot | guardian check 11 | `attacks.mjs` registry-planted-key-in-timelock | 1 | local |
| Stale or malicious registry keys | registry-planted-key-revoked: revoke_threshold (2) members stop the pending addition | refused: KeyRevoked | refused: KeyRevoked | registry | `attacks.mjs` registry-planted-key-in-timelock | 1 | local |
| Stale or malicious registry keys | registry-pin-live: pin valid until ledger 425 | accepted | accepted | — | `attacks.mjs` registry-pin-expiry | 1 | local |
| Stale or malicious registry keys | registry-pin-expiry: proved inside the pin window, submitted after it; the registry still holds the key only as a pending addition | refused: UnknownRoot | refused: UnknownRoot | guardian check 11 | `attacks.mjs` registry-pin-expiry | 1 | local |
| Stale or malicious registry keys | registry-grace-expiry: accepted on the last ledger of the 17,280-ledger grace; refused on the next | refused: UnknownRoot | refused: UnknownRoot | guardian check 11 (registry: grace) | `email_guardian.rs` registry_grace_expiry | 1 | test host |
| Stale or malicious registry keys | registry-planted-key-after-activation: a planted key active after its 7-day timelock; the attacker's proof opens another commitment | refused: ProofRejected | refused: ProofRejected | guardian check 12 | `email_guardian.rs` registry_planted_key_after_activation_without_account_code | 1 | test host |
| Stale or malicious registry keys | registry-revoked-active-key: accepted before; two members revoke the key; refused in the revocation's ledger | refused: UnknownRoot | refused: UnknownRoot | guardian check 11 (registry: revocation) | `email_guardian.rs` registry_revoked_active_key | 1 | test host |
| Compromised inbox | inbox-without-account-code: a provider-signed email from A's inbox for the attacker's attempt, A's commitment, a guessed account code | refused: recovery: the From address does not open the commitment | refused: recovery: the From address does not open the commitment | circuit | `attacks.mjs` inbox-without-account-code | 4 | local |
| Compromised inbox | inbox-without-account-code-proof: the attacker's real proof for its own guess; without the code it cannot build the salted pin's path, and the registry has no accepted root yet | refused: UnknownRoot | refused: UnknownRoot | guardian check 11 | `attacks.mjs` inbox-without-account-code | 4 | local |
| Compromised inbox | inbox-backup-without-passphrase: the backup block in the Sent folder, opened with another passphrase | refused: BackupError | refused: BackupError | account code backup (Argon2id, AES-256-GCM) | `attacks.mjs` inbox-without-account-code | 4 | local |
| Compromised inbox | inbox-with-code-quorum: the email vote counted (attempt still Collecting, 1 of 2 votes); completion refused: no authorized attempt | refused: AttemptNotLive | refused: AttemptNotLive | Perch controller | `attacks.mjs` inbox-with-account-code-quorum | 4 | local |
| Compromised inbox | inbox-email-plus-delay-authorizes: quorum 1, delay 120,960 ledgers: the attempt is Authorized, executable after ledger 121419 | accepted | accepted | — | `attacks.mjs` inbox-email-plus-delay | 4 | local |
| Compromised inbox | inbox-email-plus-delay-completion: completion inside the delay | refused: NotExecutableYet | refused: NotExecutableYet | Perch controller | `attacks.mjs` inbox-email-plus-delay | 4 | local |
| Compromised inbox | inbox-email-plus-delay-alerts: attempt_authorized: 1 email to the enrolled inbox, deleted by the thief; the push carries the code 562 261 and leads with cancelling | owner alerted: push only | owner alerted: push only | alert path | `attacks.mjs` inbox-email-plus-delay | 4 | local |
| Compromised inbox | inbox-email-plus-delay-owner-cancels: the owner's passkey cancels within the delay | accepted | accepted | — | `attacks.mjs` inbox-email-plus-delay | 4 | local |
| Compromised inbox | inbox-email-plus-delay-cancelled: completion of the cancelled attempt | refused: AttemptNotLive | refused: AttemptNotLive | Perch controller | `attacks.mjs` inbox-email-plus-delay | 4 | local |
| Compromised inbox | inbox-email-plus-delay-new-attempt: a new attempt needs a new email | refused: DigestMismatch | refused: DigestMismatch | guardian check 2 | `attacks.mjs` inbox-email-plus-delay | 4 | local |
| Compromised inbox | inbox-email-vote-alerted: the email vote recorded below quorum (attempt Collecting, 1 of 2): read from the watched attempt, alerted in 22 ms after the read | alerted: email and push | alerted: email and push | alert path | `attacks.mjs` inbox-email-vote-alerted | 4 | local |
| Compromised inbox | inbox-email-vote-owner-cancels: the owner's passkey cancels the collecting attempt | accepted | accepted | — | `attacks.mjs` inbox-email-vote-alerted | 4 | local |
| Alert path | alerts-watcher-outage: attempt_authorized never read from the event stream; reconciliation from the controller's state found it (3 accounts read, 1 alert found) | alerted after the restart: email and push | alerted after the restart: email and push | alert path (reconciliation) | `attacks.mjs` alerts-watcher-outage | 4 | local |
| Alert path | alerts-lapsed-push: residual risk: the push service answers 404 for the expired subscription, the vault marks it lapsed and emails the enrolled inbox, which the thief deletes; unless the owner opens the wallet, the attempt completes after the delay | owner alerted: nothing | owner alerted: nothing | alert path | `attacks.mjs` alerts-lapsed-push | 4 | local |
| Alert path | alerts-lapsed-push-wallet-reads: what a wallet opened during the delay reads, independent of alerts (its activity gate's authorized attempt), and offers to cancel | the controller names the attempt | the controller names the attempt | — | `attacks.mjs` alerts-lapsed-push | 4 | local |
| Phishing and social engineering | social-phished-email-counts: the victim's own email for the phisher's statement is a valid approval: the proof binds the statement, not the sender's intent | accepted | accepted | — | `attacks.mjs` social-phished-holds-passkey | 1 | local |
| Phishing and social engineering | social-phished-alerts-say-cancel: push: "This device has your passkey, so you do not need a recovery. Cancel it unless you are deliberately replacing this passkey." | push leads with cancelling; email says Nido never asks | push leads with cancelling; email says Nido never asks | alert path | `attacks.mjs` social-phished-holds-passkey | 4 | local |
| Phishing and social engineering | social-phished-owner-cancels: the victim's passkey cancels within the delay | accepted | accepted | — | `attacks.mjs` social-phished-holds-passkey | 4 | local |
| Phishing and social engineering | social-phished-cancelled: the phisher's completion of the cancelled attempt | refused: AttemptNotLive | refused: AttemptNotLive | Perch controller | `attacks.mjs` social-phished-holds-passkey | 4 | local |
| Phishing and social engineering | social-lost-devices-email-plus-delay: residual risk: email plus delay with nobody to cancel completes after the delay, installing the phisher's key (the delay is 20 ledgers here, outside the wallet's policy, so it elapses within the run; the wallet requires 120,960) | accepted | accepted | — | `attacks.mjs` social-phished-lost-devices | 4 | local |
| Phishing and social engineering | social-lost-devices-second-helper: with a second helper required, the phished email vote leaves the attempt collecting and it cannot complete | refused: AttemptNotLive | refused: AttemptNotLive | Perch controller | `attacks.mjs` social-phished-lost-devices | 4 | local |
| Repeated attempts | griefing-repeated-attempts: attempt_begun alerts nothing by default (the vault only watches each attempt for an email vote); the wallet shows open attempts from the controller, each granting nothing | owner receives: 0 emails, 0 pushes; the wallet lists 10 open attempts | owner receives: 0 emails, 0 pushes; the wallet lists 10 open attempts | alert path | `attacks.mjs` griefing-repeated-attempts | 4 | local |
| Provider header quirks | quirks-encoded-word-subject: RFC 2047 B and Q encoded-word Subjects, and the iCloud web form | refused: 3 of 3 | refused: 3 of 3 | circuit | `attacks.mjs` forged-emails-circuit | 1 | local |
| Provider header quirks | quirks-split-subject: a fold inside the value, whitespace inside the phrase | refused: 2 of 2 | refused: 2 of 2 | circuit | `attacks.mjs` forged-emails-circuit | 1 | local |
| Provider header quirks | quirks-each-provider: each launch domain's recovery email in its provider's format counts one vote | accepted: 11 of 11 | accepted: 11 of 11 | — | `attacks.mjs` quirks-each-provider | 1 | local |
| Provider header quirks | quirks-folded-subject: a Subject folded at a space counts one vote | accepted | accepted | — | `attacks.mjs` quirks-folded-subject | 1 | local |
| Provider header quirks | quirks-whitespace-subject: runs of spaces and tabs in the Subject count one vote | accepted | accepted | — | `attacks.mjs` quirks-whitespace-subject | 1 | local |
| Front-running | front-running-copy-first: the observer's copy recorded the guardian's single vote for the same attempt; the owner's own submission adds nothing | refused: AlreadyCounted | refused: AlreadyCounted | Perch controller | `attacks.mjs` front-running-copy-first | 3 | local |
| Front-running | front-running-redirect-cancel: the copy as a cancellation of the same attempt | refused: DigestMismatch | refused: DigestMismatch | guardian check 2 | `attacks.mjs` front-running-redirect | 3 | local |
| Front-running | front-running-redirect-attempt: the copy for an attacker's new attempt on the same account | refused: DigestMismatch | refused: DigestMismatch | guardian check 2 | `attacks.mjs` front-running-redirect | 3 | local |
| Front-running | front-running-redirect-account: the copy for a new attempt on another account with the same address | refused: DigestMismatch | refused: DigestMismatch | guardian check 2 | `attacks.mjs` front-running-redirect | 3 | local |
| Privacy on chain | privacy-no-address-on-chain: a sanity check, not evidence of hiding: envelopes, results and metadata of every transaction of the run, decoded and as base64, searched for each of 24 inboxes' address (raw, lower and upper case, hex, base64), its packed 31-byte limbs as field words, its account code and its pin's salt leaf | none of 213 | none of 213 | — | `attacks.mjs` privacy-no-address-on-chain | 2 | local |

Every row's observed outcome is its expected one (68 rows).

<details><summary>The circuit's verdict on each adversarial email of the mocks, built for a live attempt (forged-emails-circuit)</summary>

| Case | Mocks' verdict | Key tree | Outcome | Same as `attacks.test.ts` |
| --- | --- | --- | --- | --- |
| from-display-name-is-address | valid-dkim-but-must-be-rejected-by-circuit | pin | recovery: the From address does not open the commitment | yes |
| from-display-name-holds-angle-address | valid-dkim-but-must-be-rejected-by-circuit | pin | From: the field must hold exactly one angle-addr | yes |
| from-angle-addr-with-space | valid-dkim-but-must-be-rejected-by-circuit | planted | From: the field must hold exactly one angle-addr | yes |
| from-display-name-overlong | valid-dkim-but-must-be-rejected-by-circuit | pin | From: the field must hold exactly one angle-addr | yes |
| from-quoted-local-part | valid-dkim-but-must-be-rejected-by-circuit | pin | From: invalid character in the local part | yes |
| from-comment-before-address | valid-dkim-but-must-be-rejected-by-circuit | pin | From: invalid character in the local part | yes |
| from-comment-after-address | valid-dkim-but-must-be-rejected-by-circuit | pin | From: the field must hold exactly one angle-addr | yes |
| from-folded-relaxed | valid-dkim-but-must-be-rejected-by-circuit | pin | recovery: the From address does not open the commitment | yes |
| from-folded-simple-canonicalization | valid-dkim-but-must-be-rejected-by-circuit | pin | header: folded header line | yes |
| unsigned-subject-prepended-gmail | invalid-dkim | pin | header: exactly one signed Subject field is required | yes |
| unsigned-subject-appended-gmail | invalid-dkim | pin | header: exactly one signed Subject field is required | yes |
| unsigned-from-prepended-gmail | invalid-dkim | pin | header: exactly one signed From field is required | yes |
| unsigned-from-appended-gmail | invalid-dkim | pin | header: exactly one signed From field is required | yes |
| unsigned-subject-prepended-outlook | valid-dkim-but-must-be-rejected-by-circuit | planted | Subject: value does not open to the statement digest | yes |
| unsigned-subject-appended-outlook | invalid-dkim | planted | RSA: signature does not verify | yes |
| unsigned-from-prepended-outlook | valid-dkim-but-must-be-rejected-by-circuit | planted | recovery: the From address does not open the commitment | yes |
| unsigned-from-appended-outlook | invalid-dkim | planted | RSA: signature does not verify | yes |
| unsigned-subject-prepended-icloud | valid-dkim-but-must-be-rejected-by-circuit | planted | Subject: value does not open to the statement digest | yes |
| unsigned-subject-appended-icloud | invalid-dkim | planted | RSA: signature does not verify | yes |
| unsigned-from-prepended-icloud | valid-dkim-but-must-be-rejected-by-circuit | planted | recovery: the From address does not open the commitment | yes |
| unsigned-from-appended-icloud | invalid-dkim | planted | RSA: signature does not verify | yes |
| unsigned-subject-prepended-yahoo | invalid-dkim | planted | header: exactly one signed Subject field is required | yes |
| unsigned-subject-appended-yahoo | invalid-dkim | planted | header: exactly one signed Subject field is required | yes |
| unsigned-from-prepended-yahoo | invalid-dkim | planted | header: exactly one signed From field is required | yes |
| unsigned-from-appended-yahoo | invalid-dkim | planted | header: exactly one signed From field is required | yes |
| unsigned-subject-prepended-proton | invalid-dkim | planted | header: exactly one signed Subject field is required | yes |
| unsigned-subject-appended-proton | invalid-dkim | planted | header: exactly one signed Subject field is required | yes |
| unsigned-from-prepended-proton | invalid-dkim | planted | header: exactly one signed From field is required | yes |
| unsigned-from-appended-proton | invalid-dkim | planted | header: exactly one signed From field is required | yes |
| unsigned-subject-prepended-fastmail | invalid-dkim | planted | header: exactly one signed Subject field is required | yes |
| unsigned-subject-appended-fastmail | invalid-dkim | planted | header: exactly one signed Subject field is required | yes |
| unsigned-from-prepended-fastmail | invalid-dkim | planted | header: exactly one signed From field is required | yes |
| unsigned-from-appended-fastmail | invalid-dkim | planted | header: exactly one signed From field is required | yes |
| unsigned-subject-prepended-gmx | invalid-dkim | planted | header: exactly one signed Subject field is required | yes |
| unsigned-subject-appended-gmx | invalid-dkim | planted | header: exactly one signed Subject field is required | yes |
| unsigned-from-prepended-gmx | invalid-dkim | planted | header: exactly one signed From field is required | yes |
| unsigned-from-appended-gmx | invalid-dkim | planted | header: exactly one signed From field is required | yes |
| multiple-signatures-one-valid | valid-dkim-but-must-be-rejected-by-circuit | planted | DKIM: d= must equal the From domain | yes |
| misaligned-d-gappssmtp | valid-dkim-but-must-be-rejected-by-circuit | planted | DKIM: d= must equal the From domain | yes |
| misaligned-d-onmicrosoft | valid-dkim-but-must-be-rejected-by-circuit | planted | DKIM: d= must equal the From domain | yes |
| weak-key-rsa1024 | valid-dkim-but-must-be-rejected-by-circuit | planted | RSA: modulus is shorter than 2048 bits | yes |
| signature-plus-modulus | invalid-dkim | pin | RSA: signature is not below the modulus | yes |
| wrong-body-hash | invalid-dkim | pin | accepted | yes |
| from-not-signed | invalid-dkim | pin | header: exactly one signed From field is required | yes |
| body-length-tag | valid-dkim-but-must-be-rejected-by-circuit | pin | Subject: value does not open to the statement digest | yes |
| subject-encoded-word-b | valid-dkim-but-must-be-rejected-by-circuit | pin | Subject: must start with the recovery phrase | yes |
| subject-encoded-word-icloud-web | valid-dkim-but-must-be-rejected-by-circuit | planted | Subject: must start with the recovery phrase | yes |
| subject-encoded-word-q | valid-dkim-but-must-be-rejected-by-circuit | pin | Subject: must start with the recovery phrase | yes |
| subject-folded-at-space | valid-dkim-and-must-be-accepted | pin | accepted | yes |
| subject-extra-whitespace | valid-dkim-and-must-be-accepted | pin | accepted | yes |
| subject-value-split-by-fold | valid-dkim-but-must-be-rejected-by-circuit | pin | Subject: value must be lowercase hex | yes |
| subject-phrase-split-by-whitespace | valid-dkim-but-must-be-rejected-by-circuit | pin | Subject: must start with the recovery phrase | yes |
| recovery-value-in-display-name | valid-dkim-but-must-be-rejected-by-circuit | pin | Subject: must start with the recovery phrase | yes |
| recovery-value-in-body | valid-dkim-but-must-be-rejected-by-circuit | pin | Subject: must start with the recovery phrase | yes |
| replay-other-statement | valid-dkim-but-must-be-rejected-by-circuit | pin | Subject: value does not open to the statement digest | yes |
| replay-other-account | valid-dkim-but-must-be-rejected-by-circuit | pin | Subject: value does not open to the statement digest | yes |

</details>
<!-- END GENERATED attacks -->

### Reading the table

- **Which check refuses first.** The guardian runs its checks in order
  (spec §8.3) and the controller runs its own before asking the guardian.
  A replay is therefore refused at the first layer it fails: Perch's
  controller when the guardian already voted (`AlreadyCounted`) or the
  attempt is no longer live (`AttemptNotLive`); the guardian's check 2
  (`DigestMismatch`) when the approval carries its own statement; check 11
  (`UnknownRoot`) when it carries a root this guardian does not accept,
  which includes another account's pin root, because pins are salted with
  the account's code; check 12 (`ProofRejected`) only when every input but
  the proof is this guardian's. Checks 4 to 6 (network, account,
  controller in the statement) are not reached by any scenario: a
  statement that passes check 2 hashes to the digest the controller built,
  so it names this network, account and controller unless SHA-256 collides
  (spec A2).
- **An expired statement** is refused by the controller (`AttemptNotLive`)
  before the guardian's own expiry check (check 9) runs, because the
  statement's `valid_until_ledger` is the attempt's evidence deadline.
- **A body replaced after signing** (`forged-wrong-body-hash`) is accepted
  and counts one vote: the provider's signature covers the header block,
  which is all the proof binds (spec §4.4).
- **Accepted rows that are residual risks.** `social-phished-email-counts`
  (the phished victim's own email is a valid vote),
  `social-lost-devices-email-plus-delay` (with nobody to cancel, email plus
  delay completes) and `alerts-lapsed-push` (no alert reaches the owner)
  record what the design does not stop (spec §11.4); their expected outcome
  is that result.

## Testnet

`testnet/run.sh` deploys the email-recovery contracts to Stellar testnet
from the wasm `just build-contracts` writes, with friendbot-funded
throwaway keys (`DEPLOYED.md`, "Email recovery (evaluation, TEST-ONLY)"):
the email verifier (its reported circuit id read back), the DKIM key
registry with spec §7.6's proposed governance and the DNS attester mock's
TEST-ONLY keys, the enclave-image registry with one signer, and the email
guardian's wasm. The registry admits the Gmail mock's TEST-ONLY key through
a proposal, three approvals and two attestations; the addition then waits
in its 72-hour timelock. On Perch's testnet deployment and Nido's testnet
factory (the wallet's `perch.TESTNET`) the run then makes one complete
email-factor recovery: mint an account with a TEST-ONLY owner passkey,
deploy its guardian with a pin over the Gmail mock's key, enroll recovery
with the guardian and one helper (quorum 2, a 12-ledger delay), open a
lost-key attempt, sign the recovery email with the Gmail mock for the
controller's statement, prove it with bb.js in Node, submit the email vote
and the helper's vote, wait out the delay, and complete; the account's
document then holds the new passkey and not the lost one. Every
transaction is read back from the network (`results/testnet.json`): its
hash, the declared resources, the envelope's size, the fee charged with its
rent, the wall clock of each step, and the host's metered figures when the
RPC returns its `core_metrics` events (testnet's did). The mail provider
and DNS stay mocked; the alert path is not run on testnet.

**A precondition the run found.** Perch's doc compiler and recovery
controller, instance and code, were archived on testnet. An enrollment's
`apply_doc` reaches both, and restoring them inside it declares more write
bytes than a transaction may (`txSorobanInvalid`), so the run restores each
archived entry first in its own `RestoreFootprint` transaction (the restore
rows of the table; the two code entries' rent dominates their fee). Any
wallet enrolling on that deployment meets the same precondition until the
entries are live again.

**Comparison with the other environments.** Testnet's metered count for the
email vote is close to the test host's and about 1.6 million above the local
network's; testnet runs protocol 29 on core 30 and the local network protocol
28 on core 29 (both read from the RPCs' `getVersionInfo`), and the networks'
cost parameters are not compared here. Entries, bytes and the transaction's
size are the same as on the local network. The fee differs with the network's
fee settings: testnet charged about half of what the local network charged.
As on the local network, the vote that authorizes the attempt (here the
helper's, the second of a 2-of-2 quorum) pays the rent of the authorized
attempt's record.

## On-chain cost of an email vote

Three readings of the same call, one `submit_guardian` carrying an email
approval with a real proof:

- **Test host** (`onchain.md`, `measure-onchain.py`): `cost_estimate()` of
  the invocation in the integration tests, and the same call re-executed as
  a signed transaction in a fresh host, priced with the SDK's snapshot of
  mainnet fee rates. Not a network.
- **Local network** (below): every accepted email vote of the attack run,
  read back from the network. The instruction and byte counts are the
  host's own metering (`core_metrics` diagnostic events, which quickstart
  emits); the fee is what the network charged at its fee settings.
- **Testnet** (below): the same readings for the steps of one complete
  recovery.

<!-- BEGIN GENERATED cost by report.mjs; do not edit -->
Local network: every accepted email vote of the attack run, each `submit_guardian` with a real proof, simulated with its authorization entry enforced and sent; figures read from each transaction's result and the host's `core_metrics` events. 20 votes leave their attempt collecting (a 2-of-n quorum); 1 authorizes its attempt (the email-plus-delay account, quorum 1, delay 120,960 ledgers), which also writes the authorized attempt.

| Figure | Vote, attempt still collecting: median (range), 20 | Vote that authorizes the attempt |
| --- | --- | --- |
| Instructions (metered) | 120,033,543 (119,948,955 to 120,081,003) | 120,911,540 |
| Instructions (declared in the transaction) | 124,908,370 (124,822,347 to 124,959,677) | 125,868,498 |
| Memory bytes (metered) | 5,511,336 (5,508,900 to 5,512,554) | 5,593,647 |
| Ledger entries read (metered) | 12 (12 to 12) | 16 |
| Ledger entries written (metered) | 2 (2 to 2) | 4 |
| Ledger bytes read from disk (metered) | 0 (0 to 0) | 0 |
| Ledger bytes written (metered) | 1,208 (1,208 to 1,208) | 1,488 |
| Footprint entries (read-only + read-write) | 12 (12 to 12) | 16 |
| Signed envelope bytes | 18,080 (18,080 to 18,080) | 18,396 |
| Authorization entry bytes | 16,784 (16,784 to 16,784) | 16,784 |
| Fee charged (stroops) | 176,219 (176,158 to 176,254) | 3,734,691 |
| of which rent (stroops) | 2,604 (2,600 to 2,604) | 3,550,194 |
| Resource fee declared (stroops) | 192,567 (192,506 to 192,602) | 4,283,482 |
| Wall clock, simulation to confirmation (ms) | 1,363 (578 to 1,872) | 1,072 |

The same call, the email vote with a real proof, in each environment (instructions; footprint as read-only + read-write entries). Test host from `onchain.md`; local network from this run; testnet from `results/testnet.json` (Gmail only).

| Domain | Test host invocation | Test host transaction | Test host footprint | Local network, metered | Local network, declared | Local footprint | Testnet, metered |
| --- | --- | --- | --- | --- | --- | --- | --- |
| fastmail.com | 121,857,413 | 131,203,427 | 12 + 2 | 120,072,887 | 124,948,616 | 10 + 2 |  |
| gmail.com | 121,817,031 | 131,165,581 | 12 + 2 | 120,044,323 | 124,921,530 | 10 + 2 | 121,639,784 |
| gmx.de | 121,873,343 | 131,218,607 | 12 + 2 | 120,066,331 | 124,944,418 | 10 + 2 |  |
| gmx.net | 121,855,989 | 131,203,739 | 12 + 2 | 119,992,971 | 124,868,124 | 10 + 2 |  |
| hotmail.com | 121,916,929 | 131,256,349 | 12 + 2 | 120,036,207 | 124,910,468 | 10 + 2 |  |
| icloud.com | 121,863,515 | 131,203,635 | 12 + 2 | 120,081,003 | 124,959,677 | 10 + 2 |  |
| outlook.com | 121,834,651 | 131,176,986 | 12 + 2 | 120,029,651 | 124,906,271 | 10 + 2 |  |
| proton.me | 121,801,947 | 131,149,797 | 12 + 2 | 120,007,643 | 124,883,383 | 10 + 2 |  |
| protonmail.com | 121,833,559 | 131,173,379 | 12 + 2 | 120,044,273 | 124,921,010 | 10 + 2 |  |
| web.de | 121,817,039 | 131,165,789 | 12 + 2 | 120,036,987 | 124,913,900 | 10 + 2 |  |
| yahoo.com | 121,806,163 | 131,142,707 | 12 + 2 | 120,014,199 | 124,887,580 | 10 + 2 |  |

The registry is in the footprint of 0 of the 21 local votes: each local approval is proven against its guardian's key pin (no registry key activates during a local run), so the guardian accepts the root without calling the registry. The test host's approvals use a registry root, and its footprints include the registry's instance and code.

Testnet (`Test SDF Network ; September 2015`, https://soroban-testnet.stellar.org, Stellar RPC 30.0.0-13e53516633c3ce1281c7edbacb607107d3a4e55), run of 2026-11-02 02:16 UTC: one complete email-factor recovery, 23 transactions. Proving (bb.js in Node, on the machine of the proving table): 0.7 s witness, 3.4 s proving.

| Step | Transaction | Instructions (metered) | Instructions (declared) | Read / write entries | Bytes written | Envelope bytes | Fee charged (stroops) | of which rent | Wall clock (ms) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| deploy the email contracts (upload nido_email_verifier) | [`d4c48e05c842…`](https://stellar.expert/explorer/testnet/tx/d4c48e05c842663c2094f5bea4c740cf1f085d51fa69847eabb8e9470deed9f4) | 39,379,581 | 40,956,128 | 1 / 0 | 0 | 45,864 | 113,050 | 0 | 3,586 |
| deploy the email contracts (deploy nido_email_verifier) | [`a225fea7f32c…`](https://stellar.expert/explorer/testnet/tx/a225fea7f32c099c0de77f8b68624f63de1792f0b30339a9bafdc5426111a4e5) | 619,073 | 670,448 | 2 / 1 | 104 | 536 | 14,842 | 11,383 | 2,048 |
| deploy the email contracts (upload nido_dkim_registry) | [`1096b46c5fb1…`](https://stellar.expert/explorer/testnet/tx/1096b46c5fb1a9080e4eea235eae9fd6072399bc4ff226957b8509b0f1ddaa52) | 58,457,223 | 60,796,876 | 1 / 0 | 0 | 68,520 | 168,386 | 0 | 7,002 |
| deploy the email contracts (deploy nido_dkim_registry) | [`b9e490ae2318…`](https://stellar.expert/explorer/testnet/tx/b9e490ae231885476a1f6ca264e3eb513b5d06532b80804a00faadd15c6e3ff3) | 1,565,195 | 1,630,603 | 2 / 1 | 1,116 | 2,088 | 2,810,024 | 2,802,463 | 1,965 |
| deploy the email contracts (upload nido_enclave_image_registry) | [`94578fb9ea0d…`](https://stellar.expert/explorer/testnet/tx/94578fb9ea0d6d4aba53e74c3732d24da72aab4fca4ebc1937c63449edaed0d5) | 9,615,493 | 10,001,477 | 1 / 0 | 0 | 10,400 | 26,463 | 0 | 2,662 |
| deploy the email contracts (deploy nido_enclave_image_registry) | [`769923dc1864…`](https://stellar.expert/explorer/testnet/tx/769923dc18640a2b30e46b195ef83d1d977a28190d28cba3c3e6ebd9f4570427) | 848,131 | 902,617 | 2 / 1 | 208 | 664 | 528,537 | 524,686 | 6,559 |
| deploy the email contracts (upload nido_email_guardian) | [`86c04faf160c…`](https://stellar.expert/explorer/testnet/tx/86c04faf160c5c934d2b22485909e34cfe36fb1413e091b156d5f4c5173fb3d0) | 29,145,959 | 30,313,161 | 1 / 0 | 0 | 33,728 | 83,404 | 0 | 7,383 |
| registry: propose, approve and attest the Gmail mock key (registry propose_add gmail.com) | [`12b5f3b5c199…`](https://stellar.expert/explorer/testnet/tx/12b5f3b5c199c40e99c6ce8db8d8f11e04cc8cd731ae0992560a881b2ca8f792) | 9,496,461 | 9,884,886 | 4 / 2 | 1,536 | 1,324 | 1,066,944 | 1,055,385 | 1,253 |
| registry: propose, approve and attest the Gmail mock key (registry approve 1) | [`c263b7cae164…`](https://stellar.expert/explorer/testnet/tx/c263b7cae16449e77c723cb3e72e32b39caf2874f1b696f8992a11d2fa2f8013) | 763,970 | 818,641 | 3 / 1 | 420 | 592 | 5,462 | 1,272 | 2,167 |
| registry: propose, approve and attest the Gmail mock key (registry approve 1) | [`878c6aa117c8…`](https://stellar.expert/explorer/testnet/tx/878c6aa117c876b5786b83fb493a22edada8798f6a469b207dbe9327d74448b2) | 765,064 | 819,735 | 3 / 1 | 424 | 592 | 15,463 | 11,272 | 1,970 |
| registry: propose, approve and attest the Gmail mock key (registry attest 1 by 0) | [`620ddaefcd15…`](https://stellar.expert/explorer/testnet/tx/620ddaefcd15128f2d91c05f1a09676303ae609840d0533264285fa7f1b57eb0) | 1,652,268 | 1,725,299 | 3 / 1 | 436 | 808 | 36,661 | 31,272 | 2,059 |
| registry: propose, approve and attest the Gmail mock key (registry attest 1 by 1) | [`b57602eacedc…`](https://stellar.expert/explorer/testnet/tx/b57602eacedc43f3d5165c7d715d53bcab8cc8542d7ec3d6c0085999d572c955) | 1,654,248 | 1,727,358 | 3 / 1 | 452 | 808 | 46,668 | 41,272 | 1,751 |
| restore Perch's archived entries (doc compiler instance, doc compiler code, recovery controller instance, recovery controller code) (restore doc compiler instance) | [`6b85123a745b…`](https://stellar.expert/explorer/testnet/tx/6b85123a745b7d284323a84342b2f43c1934d32b9d3079c3e74ecf657ff42423) | — | 0 | 1 (footprint) | 104 | 252 | 14,726 | 11,383 | 2,040 |
| restore Perch's archived entries (doc compiler instance, doc compiler code, recovery controller instance, recovery controller code) (restore doc compiler code) | [`b39e79d0d692…`](https://stellar.expert/explorer/testnet/tx/b39e79d0d692365534c30a73f7f9e0aee77fd685f20016aa711b62ebac624a93) | — | 0 | 1 (footprint) | 110,048 | 240 | 78,873,057 | 78,798,878 | 1,900 |
| restore Perch's archived entries (doc compiler instance, doc compiler code, recovery controller instance, recovery controller code) (restore recovery controller instance) | [`b9d82df040d8…`](https://stellar.expert/explorer/testnet/tx/b9d82df040d8d558fa1780b0c0824e676bd09fbede619765f447a2ae76f5776d) | — | 0 | 1 (footprint) | 104 | 252 | 14,726 | 11,383 | 2,076 |
| restore Perch's archived entries (doc compiler instance, doc compiler code, recovery controller instance, recovery controller code) (restore recovery controller code) | [`9806a648675c…`](https://stellar.expert/explorer/testnet/tx/9806a648675c4b0cfeadb4b501dc2a7c8ae71ad2fa7bc55ad20560d6994bed79) | — | 0 | 1 (footprint) | 68,364 | 240 | 33,545,398 | 33,498,086 | 6,830 |
| enroll: mint, deploy the guardian, apply the recovery document (mint testnet) | [`25bb1939faec…`](https://stellar.expert/explorer/testnet/tx/25bb1939faeca1678387d15bd13eb8e86dd4a59cf8b0d39b79886652dbbad400) | 3,303,767 | 3,469,152 | 10 / 5 | 1,468 | 1,064 | 1,344,343 | 1,331,243 | 5,022 |
| enroll: mint, deploy the guardian, apply the recovery document (deploy guardian testnet) | [`4381a327a06d…`](https://stellar.expert/explorer/testnet/tx/4381a327a06d03ae43310a7d46a6e020c501be4be10fee9d4ef2052d7a1a7ac2) | 1,230,050 | 1,283,007 | 4 / 1 | 644 | 1,660 | 1,623,015 | 1,616,693 | 1,796 |
| enroll: mint, deploy the guardian, apply the recovery document (apply_doc testnet) | [`24c2b9594a6a…`](https://stellar.expert/explorer/testnet/tx/24c2b9594a6a50493013b986220a9ebf00bea5122eb84bcfb02b9cc4fc969066) | 16,241,550 | 17,010,106 | 22 / 10 | 3,852 | 4,204 | 5,711,754 | 5,681,123 | 3,858 |
| begin_lost_key | [`6e3a7e8c0892…`](https://stellar.expert/explorer/testnet/tx/6e3a7e8c0892fa9d54e98e93554c18abf277c7f19d8fc655b5ad8b10218ede82) | 13,121,774 | 13,690,643 | 16 / 2 | 1,236 | 1,844 | 365,909 | 353,423 | 1,864 |
| submit_guardian (email vote, real proof) | [`08cdc915727c…`](https://stellar.expert/explorer/testnet/tx/08cdc915727cc9b569bd4015ea01a33fa5486d2d18cb673d30ab7d393b5810ff) | 121,639,784 | 126,548,373 | 12 / 2 | 1,208 | 18,080 | 82,428 | 1,333 | 1,715 |
| submit_guardian (helper vote) | [`e1e4b757c083…`](https://stellar.expert/explorer/testnet/tx/e1e4b757c0833fdad4eea9156853ec6278715c7d81eccf79a2cd8bf0961c16bc) | 2,064,633 | 2,202,593 | 11 / 3 | 1,460 | 1,504 | 3,664,628 | 3,653,812 | 2,422 |
| the delay | — | | | | | | | | 57,575 |
| complete (apply_doc through the recovery rule) | [`ff431206c9e3…`](https://stellar.expert/explorer/testnet/tx/ff431206c9e3c9ad4d0880fececaec432b95ef159a531bbf58641d7889037be4) | 14,897,208 | 15,746,781 | 27 / 12 | 5,264 | 4,256 | 592,637 | 552,040 | 3,431 |
<!-- END GENERATED cost -->

**Comparison.** The same proof and statement shape give nearly the same
call everywhere; three things differ, and only the first is attributed.

- *The key path.* Every local (and testnet) approval is proven against its
  guardian's key pin, because no registry key activates during a run, so
  the guardian accepts the root without calling the registry. The test
  host's approvals use a registry root: its transaction footprint for the
  Gmail fixture, read from what `nido_integration_tests::transaction::measure`
  records, lists the registry's instance and code among its 12 read-only
  entries, the two the local footprints (10 + 2) do not have, and the
  registry's `is_accepted_root` costs about 564,000 instructions there (spec §12).
- *Metering.* The local network's metered count is below the test host's
  invocation count by more than the registry call. The rest is not
  attributed here: each host meters with its own cost parameters (the SDK's
  built-in ones on the test host, the network configuration's on a
  network), and this evaluation does not compare them. Bytes written (1,208)
  and the authorization entry (16,784 bytes around the 16,224-byte proof)
  are the same everywhere.
- *Fees.* Each environment prices with its own fee settings: the test-host
  transaction reading uses the SDK's snapshot of mainnet rates without rent;
  the local network charges at quickstart's settings, rent included.

## Proving

<!-- BEGIN GENERATED proving by report.mjs; do not edit -->
Generated by `research/email-recovery/eval/proving/measure.mjs` on 2026-11-02 00:52 UTC (browser rows: `measure-browser.mjs`, 2026-11-02T00:38:38.899Z).
Machine: Apple M5 Max, 18 logical CPUs (6 performance and 12 efficiency cores), 128 GiB, macOS 26.5.2, Node v24.18.0; load average 5.36 5.40 5.36 at the start and 5.95 5.54 5.38 at the end; browser rows on the same machine, load average 4.59 4.88 5.17 at their start.
Circuit build: `circuits/email-recovery/artifacts/recovery.json` (sha256 `5d793cbe967bf11f…`), verification key sha256 `2837d0cfd7ddad68…` (the verifier's circuit id); nargo version = 1.0.0-beta.9, bb v0.87.0; the Gmail fixture's recovery email. Times in seconds: median (minimum to maximum) of 5 runs (browser: 5 warm runs).

| Prover | Threads | Witness (s) | Proving (s) | Total (s) | Peak memory | Runs |
| --- | --- | --- | --- | --- | --- | --- |
| Native bb, every core | 18 | 0.64 (0.63 to 0.65) | 0.94 (0.93 to 1.00) | 1.58 (1.56 to 1.65) | 879 MiB (`bb prove` RSS) | 5 |
| Native bb, one thread | 1 | 0.64 (0.63 to 0.66) | 4.67 (4.63 to 4.72) | 5.31 (5.27 to 5.38) | 872 MiB (`bb prove` RSS) | 5 |
| Native bb, efficiency cores, one thread | 1 | 2.31 (1.04 to 2.38) | 18.2 (17.2 to 18.5) | 20.6 (18.2 to 20.9) | 883 MiB (`bb prove` RSS) | 5 |
| Native bb, efficiency cores, four threads | 4 | 2.35 (2.30 to 2.42) | 6.25 (6.23 to 6.38) | 8.63 (8.55 to 8.69) | 879 MiB (`bb prove` RSS) | 5 |
| bb.js in Node, one thread | 1 | 0.76 (0.75 to 0.77) | 13.5 (13.4 to 13.6) | 14.3 (14.2 to 14.4) | 1,421 MiB (process RSS) | 5 |
| bb.js in Node, 18 threads | 18 | 0.76 (0.76 to 0.77) | 3.30 (3.29 to 3.38) | 4.06 (4.04 to 4.14) | 1,716 MiB (process RSS) | 5 |
| bb.js in Node, efficiency cores, one thread | 1 | 2.81 (2.39 to 2.86) | 56.6 (53.1 to 57.8) | 59.4 (55.9 to 60.3) | 1,352 MiB (process RSS) | 5 |
| bb.js in Node, efficiency cores, four threads | 4 | 2.77 (2.73 to 2.86) | 21.5 (21.2 to 23.2) | 24.3 (24.0 to 26.0) | 1,446 MiB (process RSS) | 5 |
| Chrome/151.0.7922.34 (headless), one thread | 1 | 0.80 (0.80 to 0.81) | 8.42 (8.35 to 8.46) | 9.96 (9.88 to 9.98) | 1,468 MiB (renderer RSS); 738 MiB Barretenberg memory | 5 |
| Chrome/151.0.7922.34 (headless), 18 threads | 18 | 0.77 (0.75 to 0.80) | 1.48 (1.46 to 1.53) | 2.92 (2.85 to 3.06) | 2,616 MiB (renderer RSS); 805 MiB Barretenberg memory | 5 |
| Chrome/151.0.7922.34 (headless), efficiency cores, one thread | 1 | 3.04 (2.83 to 3.11) | 36.4 (35.6 to 37.0) | 41.3 (41.2 to 42.9) | 1,428 MiB (renderer RSS); 738 MiB Barretenberg memory | 5 |
| Chrome/151.0.7922.34 (headless), efficiency cores, 4 threads | 4 | 3.02 (2.93 to 3.08) | 12.0 (11.5 to 12.3) | 17.5 (16.7 to 18.1) | 2,015 MiB (renderer RSS); 771 MiB Barretenberg memory | 5 |
| Phone-class device | — | not measured | not measured | not measured | not measured | 0 |

Witness: native `nargo execute`; Node the encoder and noir_js; browser the encoder and noir_js in the prover worker. Total: native and Node witness plus proving; browser from the page's request to the locally verified proof (cached assets, Barretenberg's start and the verification included).
<!-- END GENERATED proving -->

**Reading the table.**

- Every row proves the same circuit build and the same email: the
  committed artifact, whose verification key `measure.mjs` checks against
  the verifier's circuit id before it measures, and the Gmail fixture.
- Native `bb` is the fastest everywhere; bb.js is the same library in Node
  and in Chrome. On one thread Chrome's prover worker proved faster than
  Node did on this machine; why is not investigated here.
- The browser total includes everything the page waits for (the cached
  assets, Barretenberg's start, the local verification): on 18 threads
  proving itself is about half of the total.
- Peak memory differs in kind per prover (the `bb` process, the Node
  process with its workers, the browser's renderer), so the columns are not
  directly comparable; Barretenberg's own wasm memory in the browser is
  738 MiB on one thread.

The DevTools CPU-throttling rows of `browser-prover.md` are not repeated
here: Chrome applies that throttling to the page only, never to the
workers that prove, so they show desktop proving speed.

**On a phone.** No phone was reachable. `just email-recovery-bench-phone`
builds the benchmark page as a self-contained directory
(`phone/build.mjs`: the page, its assets, the circuit, its key, the
TEST-ONLY Gmail fixture, and the CRS prefix checked against the prover's
pinned digests) and serves it over HTTPS on this machine's network
addresses with the recovery routes' isolation headers (`phone/serve.mjs`).
Opened on a phone on the same network, after accepting the throwaway
certificate once, the page proves with one thread and with every core and
prints the JSON to copy. The phone rows of the table stay "not measured"
until that is done.

## What was run and what was read

Run, in this repository, on the machine of the proving table:

- the attack suite on a local network (`network/run-attacks.sh`), against
  contracts built from this tree and Perch's fetched testnet wasm, with every
  approval proven by bb.js in Node, and its three registry scenarios on the
  integration-test host;
- the proving measurements (`proving/measure.sh`, `measure-browser.mjs`);
- the self-contained benchmark build and its server, on this machine only.

Read, not run: Perch's controller behaviour beyond what the scenarios
exercise (its spec, `vendor/perch/docs/recovery/spec.md`); the providers'
real signing formats, which the mocks follow from their published
documentation (spec §13 question 6); quickstart's ledger timing (one ledger
about every second in local mode, from its configuration and observed in
the runs).

## Threats to validity

- **Mocked third parties.** Every email is signed by a provider mock with a
  TEST-ONLY key in that provider's published format, DNS is the mock's, and
  the alert path's sending services, push service, enclave and custodians are
  mocks. A provider whose real mail differs from its mock (spec §13
  question 6) is not covered.
- **The local network's registry state.** A local network closes about one
  ledger per second, so no key addition leaves its 72-hour or 7-day timelock
  during a run: the local scenarios run with every launch key pending and
  the accounts' pins carrying their keys. The three scenarios that need an
  activated key or an elapsed grace period run on the integration-test host
  with the registry's production wasm and real timelocks, where the ledger is
  advanced rather than waited for; that host runs the same contracts but is
  not a network.
- **The enclave-image registry stand-in.** The alert vault's custodians read
  image activation from a TEST-ONLY allowlist contract on the local network
  (as in the email end-to-end test), because the enclave-image registry's
  14-day timelock cannot elapse locally.
- **First failing check.** A scenario reports the first layer that refuses
  it. Later checks on the same path are covered by the guardian's and the
  registry's unit tests (spec §8.5, §7.6), not here.
- **Timing.** Wall-clock figures come from one shared machine whose load
  average is recorded; other workloads ran on it. Local-network latency is
  dominated by quickstart's one-second ledgers, not by the contracts.
- **One testnet run.** The testnet figures are one recovery at one time;
  latency there depends on testnet's load and ledger timing (about 5
  seconds), and fees on its fee settings at that time.
- **Desktop, not phone.** Efficiency-core rows run a desktop's slower cores
  under macOS's background QoS; they are not a model of a phone.
- **Mechanisms, not people.** The alert-path, phishing and repeated-attempt
  rows show what reaches the owner and that a cancellation within the delay
  succeeds. Whether people read the push, recognise a phishing script, or
  cancel in time is not measured; the walkthrough (`walkthrough.md`) is an
  expert's prediction, not a study.
- **The outage model.** The watcher outage is a host that never reads the
  missed events, not an RPC that aged them out over 120,960 ledgers; the
  aged-out cursor itself is exercised against the RPC mock
  (`infra/email-alerts/test/liveness.test.ts`).

## Not measured

- Proving on a phone-class device.
- Real provider mail, real DNS, a production enclave, and real sending and
  push services.
- Mainnet.
- Alerts on testnet: the alert path runs on the local network only.

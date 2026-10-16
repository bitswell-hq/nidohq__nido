# Deployments (testnet)

What the wallet in this tree targets on testnet, with the provenance needed to
check it. Deployments that current code or existing accounts still reach, but
that the wallet does not target, are in the
[compatibility appendix](#compatibility-appendix). Every other retired
deployment is in this file's git history (`git log -p -- DEPLOYED.md`).

## Perch's stack

Perch deploys its stack; Nido deploys none of it. The record is Perch's
manifest,
[`deployments/testnet.json`](https://github.com/stellar-registry/perch/blob/603f7d5504f2d4d9338c135771cea18ac70dbe0c/deployments/testnet.json)
(`vendor/perch/deployments/testnet.json`), at the Perch commit Nido pins: for
every contract its version, wasm sha256, and content address under the
manifest's registry, plus the Perch commit and toolchain that built them and
the ledger they were deployed at. Perch's
[`scripts/verify-deployment.sh`](https://github.com/stellar-registry/perch/blob/603f7d5504f2d4d9338c135771cea18ac70dbe0c/scripts/verify-deployment.sh)
(`vendor/perch/scripts/verify-deployment.sh`) checks the manifest against the
chain by hash and address.

The wallet's deployment, `perch.TESTNET`
(`packages/passkey-sdk/src/perch/deployment.ts`), is that manifest plus Nido's
factory; `packages/passkey-sdk/src/perch/deployment.test.ts` checks every field
but `factory` against the manifest (SECURITY_INVARIANTS W6). The `factory`
address is `perch.TESTNET.factory` itself, which nothing checks; this record is
its provenance. Wasm hashes and versions are in the manifest.

| Manifest field (`PerchDeployment`) | Contract | Address or value |
| --- | --- | --- |
| `network` | | `Test SDF Network ; September 2015` |
| `factory` | `nido-factory` (Nido's, [below](#nidos-factory)) | `CBJRCUECFC2FSJBSVOVYHWC73A2SN7LIKSLWJBQUNEOWPE4PXG33M54H` |
| `webauthnVerifier` | `perch-webauthn-verifier` | `CDRYDB7O2JFLF7FAIIQUQK4BKQT3N6ACFFGZQ7AHKMX52RIWTHBHJY6K` |
| `statelessRegistry` | Perch's registry instance | `CDX2DMYMMEYU6FGN3HPJ2GQSSL5EZHIAMEJD4SPF55FZE5LEUBPPPDA7` |
| `docCompiler` | `perch-doc-compiler` | `CAV47HI46VZ4JMAN5OA7IFECNFNJHINYZMYUGN27EZI6STEHQFLW23RB` |
| `interpreter` | `perch-interpreter` | `CCYIMM4NCHFIN5JTMT4AAUCZ44SFT3AEIXDOQZV3GZE2E4ZCFGEGZPYF` |
| `spendingLimit` | `perch-spending-limit` | `CCOAFX6AJITJXF3A6PCY564DQO33TFXQSMLNB77ZQD2FLP5CSWAYM5JU` |
| `recoveryController` | `perch-recovery` | `CBUCGUBLHRPPW7DCS2RCRGNY2JAGCLH7NIJTWPYVTEZNNOOJ73YXYQI6` |
| `zkPool` | `perch-zk-pool` | `CAAUAAK4VM4GM5JHNMDQT5TDXADXWNMLEXGP5PBD5Y7DPDTFB6MIXLVJ` |
| `zkAdapter` | `perch-zk-adapter` | `CCSBNPHCA4ER3TNFXMGJCJNMTGNECFBMJUFAX5ZHM3PORP6RDCPR5TAA` |
| `circuitId` | | `9e39c41f4f35aad43e64b255dfe3ba13f10e8c9d36d6f56fce23c2d97c0a0b4a` |
| `treeDepth` | | `32` |
| `accountWasmHash` | `perch-account` (installed, not deployed) | `d99d56fc2d07a14c2259f0994d97316d23ae90db26835f4c977939c2b3b593aa` |

The SDK also derives the compiler and interpreter addresses offline, from
the registry id and their wasm hashes (`perchTestnetAddresses()` in
`packages/passkey-sdk/src/policyDoc/deployment.ts`, pinned in its
`deployment.test.ts`), and they match the table.

The manifest also lists Perch's own factory (`perch-account-factory`), which
Nido does not use: its addresses commit to the admin signers, but a Nido
passkey's RP ID is the account's own subdomain, so the address has to exist
before the passkey.

## Nido's factory

Read from the chain (the contract instance and its wasm metadata) on
2026-10-15.

| Field | Value |
| --- | --- |
| Address | `CBJRCUECFC2FSJBSVOVYHWC73A2SN7LIKSLWJBQUNEOWPE4PXG33M54H` |
| Wasm sha256 | `c858f314ed96ceca6a5da7b2a4e77b997492e84b285f7abc8c89a50335fc882d` |
| Built from | rustc 1.96.0, soroban-sdk 27.0.5, `stellar-cli` 27.0.0, `stellar-scaffold` 0.0.27 (the wasm's metadata). The Nido commit is not recorded. |
| Embeds | `perch-account` `d3d4c28a01b37660c23ac03622b712608d2c0f853b634a597f3cd617e7b66df5`, Perch `845c49a`'s ([earlier Perch generations](#earlier-perch-generations)), not the pinned manifest's `accountWasmHash` |
| Verifier pin | `CAL7IEAJO7S3SJI4EXESMUNPOEYW6QNR3PQTO7AVHD75YGURSZ5CW27Z`, Perch `845c49a`'s `perch-webauthn-verifier` (`set_registry_pins`), not the pinned manifest's |
| Admin | `GA2MQ7MBJQCIHGO3ROH7254A5MUNW34UWFHOT4Y2ZPZIHOLEBF57C22Q`, a single throwaway testnet deploy key |
| Deployed | 2026-10-12 (nidohq/nido#255), with the pin and the account hash the factory deploys read back |
| Registry name | None |

**This factory predates the pinned Perch release.** The re-pin to Perch
`cb17149` (nidohq/nido#267) did not redeploy it, so every account it creates
runs Perch `845c49a`'s account code and names that release's verifier, while
`perch.TESTNET` names the `cb17149` release. Redeploying the factory against
the pinned manifest (RUNBOOKS §2.2) and recording it here closes the gap.

## Nido contracts in use

| Name | Address | Notes |
|---|---|---|
| Factory | `CBJRCUECFC2FSJBSVOVYHWC73A2SN7LIKSLWJBQUNEOWPE4PXG33M54H` | `perch.TESTNET.factory`, recorded [above](#nidos-factory). `create_account(salt, key)` deploys a Perch account of the `845c49a` generation, whose `__check_auth` binds the account's own address into the external-signer digest (`addr_oz_v1`). Not registry-registered: `perch.TESTNET.factory` in `packages/passkey-sdk/src/perch/deployment.ts` is the source of truth. The previous Perch-era factory is `CBFDM3…` ([earlier Perch generations](#earlier-perch-generations)); the pre-Perch `CCJFOM6…` is in the compatibility appendix. |
| WebAuthn verifier | `CAL7IEAJO7S3SJI4EXESMUNPOEYW6QNR3PQTO7AVHD75YGURSZ5CW27Z` | Perch's, from its `845c49a` deployment ([earlier Perch generations](#earlier-perch-generations)), not the pinned manifest's `CDRYDB7O…`. The factory above pins it (`set_registry_pins`, read back live), so the admin rule of every account it mints names it. Constructorless, no admin. Nido's former verifier, `CACVGSAH…`, is in the compatibility appendix. |
| Multisig policy | `CCSDKJYOFCPTCCGQZPF73RJNHFC7TPO532Q36N3M2VBYZFWQOTDB7J7G` | Registered as `unverified/multisig-policy`. Built against soroban-sdk 26 + OZ stellar-contracts main — accepts v0.7 `ContextRule` (with `signer_ids`/`policy_ids`). |
| Spending-limit policy | `CCJMCPGADKMVKYOIZXMV7UWH62XYDAIT6GJRNJPQSZ2CHPOF4K2AU2QC` | Registered as `unverified/spending-limit-policy`. Built against soroban-sdk 26 + OZ stellar-contracts rev `637c53a` — wraps `policies::spending_limit` (rolling window, meters SAC `transfer`). |
| Stellar Registry (unverified) | `CDBL7MNO7UI5OAAIC67UIWKQ4P3S6RVQSFCQXUHUW6TOFCXSYRPNHY4S` | The registry the factory queries via `Self::resolve(env, name)`. |
| Name registry | `CDVVRZAVXTUQLS5LCGUP3H26RGOIUFKNE2UEJ6CAWYMBWY5LNORF6POX` | Human-readable account names. Independent of the policy-builder set. |
| Status Message demo | `CD5FK6CQ7QIZ5ONARG36Y53ERI5PIBGELSJUTD7OXYLK6EQAS4N3TFBV` | Hardcoded in `packages/frontend/src/pages/status-message/index.astro`. Predates the policy-builder work. |

## Deploying

See [docs/RUNBOOKS.md](docs/RUNBOOKS.md) §2. Record every deployment here:
address, wasm hash, deployer, commit, and `stellar-cli` version.

## Compatibility appendix

Deployments the wallet does not target but that something current still
reaches. The factory and verifier below run code that is not in this tree and
must not be deployed to mainnet; whether the pre-Perch policies reach mainnet
is MAINNET_READINESS D6. Accounts minted by an older factory are not
migrated: they keep the account code and verifier they were minted with until
their owners move to a new account.

| Name | Address | What still reaches it, and why it matters |
| --- | --- | --- |
| Factory (doc-only) | `CCJFOM6UGOH7JSAX22C3FAECG5657HKIUYDBTCMUMILKDA6LOA2J2EGG` | Embeds Nido's former smart account (wasm `fe3b1878…`). Still the registry's `factory` name and the SDK's `factory` fallback; the wallet uses it only when built without a Perch deployment (`fetchFactoryAddress`). Repointing the name is a separate, deliberate step (RUNBOOKS §2.2). |
| WebAuthn verifier (Nido's former) | `CACVGSAHYFBXY4LJKWW5B57LAAXHCZVDZOANUTYPLNV6HHQI4Q35EGMY` | Admin-upgradeable; its source is not in this tree. Registered as `verifier` and the SDK's `verifier` fallback. Every account a pre-Perch Nido factory minted names it, so its admin key remains a trust anchor for those accounts (THREAT_MODEL 7). The wallet falls back to it only when it cannot read an account's admin rule and has no Perch deployment (`fetchVerifierAddress`). |
| Multisig policy (pre-Perch) | `CCSDKJYOFCPTCCGQZPF73RJNHFC7TPO532Q36N3M2VBYZFWQOTDB7J7G` | `contracts/multisig-policy`. A Perch document can't attach it, so only accounts minted by pre-Perch factories can carry it. |
| Spending-limit policy (pre-Perch) | `CCJMCPGADKMVKYOIZXMV7UWH62XYDAIT6GJRNJPQSZ2CHPOF4K2AU2QC` | `contracts/spending-limit-policy`. A Perch document can't attach it. The wallet resolves the registry's `spending-limit-policy` to show the cap of a rule that carries it (`fetchSpendingLimit`), and to decompile documents when built without a Perch deployment. |

### Earlier Perch generations

Every Perch redeploy puts each contract at a new address (they are
content-addressed and have no admin), and an account keeps the generation it
was minted with: its wasm pins the compiler, interpreter, and spending limit,
its admin rule names the verifier, and its document names the controller,
pool, and adapter. Accounts move only through their owner's seven-day upgrade
and an `apply_doc` (RUNBOOKS §7). Two earlier generations are still in use on
testnet. Nido's factory in `perch.TESTNET` (`CBJRCUEC…`) mints the `845c49a`
account, so new accounts get that generation until the factory is
redeployed. The testnet run SECURITY_INVARIANTS W8 records used the
`7ae915d` generation. Each column is that
generation's Perch manifest, `deployments/testnet.json` in Perch's history.

| Contract | Perch `845c49a` (deployed 2026-10-12) | Perch `bb746f9`, built from `7ae915d` (deployed 2026-10-09) |
| --- | --- | --- |
| Registry (`registry.id`) | `CAR2DSSOBJB76GGD6MAAKWUK36Y7I7O3NDWTN7HTIRV5I3XZ27U3ZBVZ` | `CCUC5RDRGRFFC5VGG7HCB3OMNNSYDFAQOSA7SBGYUM2GDXAJBUWI5TFQ` |
| `perch-account` wasm | `d3d4c28a01b37660c23ac03622b712608d2c0f853b634a597f3cd617e7b66df5` (`addr_oz_v1`) | `bbb30174bbd85a2956a2f6146a156769621254011a6bdcac707cf787ce7bcd52` (`oz_rule_ids`) |
| `perch-webauthn-verifier` | `CAL7IEAJO7S3SJI4EXESMUNPOEYW6QNR3PQTO7AVHD75YGURSZ5CW27Z` | `CBCCINHRMS3COAV5RHTCUASZLOEC52FCOBR3HMU4FKWJTAHWZTVFTHHY` |
| `perch-doc-compiler` | `CCYSZHRHY7GKT2OYXF6JW332GA2BL6ZKPAWIV6RVC5JW2RNPHQPSW5ZI` | `CDHZT7NLQDPMWCUDNUVCYC2EAMGRFWABQO5WDSRJGDQVIDHOWQB2FANB` |
| `perch-interpreter` | `CA5JLPEVA3E5X7YEDVABMEM3TML33ZS3I6WL5NDBFIZZAXFYNZPBBWTO` | `CAI6RPWAJ7Z6MP3HLGMTD3W4P4DTD6BEKPFV7XF6VANC2H7XYAQHIXHP` |
| `perch-spending-limit` | `CD3FGRDBG7L5KNJAOQZW5WWKK4E5CQ63DNC3W25B63WEIGYX25NQDN4K` | `CCVXXCAKMROSWAH6QKZ2PUMMH3QUUEUERJQ3CI4XMAWVOMTKKJHYSMTF` |
| `perch-recovery` | `CDBIZB3MP7ANOFKIYBRKFX4AODLRODCDZUWMMYVTCFAXA4W2OH6D6LV2` | `CDIGZVWVXJT2PVDIAUKLX62LW7DNJBC6SZUSR6SLQ6MNICGCGZ6EEXPR` |
| `perch-zk-pool` | `CB3IOX2VW7C5VYKVQMNLQ5DPMNC5WSPEOVJSIRBZKXVHURGXBHII6EP7` | `CB46EOGM6FSSHO2TNKFWZF5AOIDROPNE6QW75XBKETX5IS757B25WK2Y` |
| `perch-zk-adapter` | `CDLOOCAYOLNIVLGD4ZT6CYCRN23SM7OPO7FOSDUASFPHNAW3VWBMY2WH` | `CBGN355IPW63XPNOSG4O3EZD46ASBXCM5W55PQHEZXJYAFZXN23BNAWC` |
| Nido factory that mints it | `CBJRCUECFC2FSJBSVOVYHWC73A2SN7LIKSLWJBQUNEOWPE4PXG33M54H` | `CBFDM3GWAYW4BFGRGDS45OKLU6BWPEKMOY6U6T3JD5E35FDDWITS4VOE`: wasm `4a16b51b268814d2b92a9801e48684adba112bc8a5225ae32ce7d88a4f95665f`, built from Nido `42738a3f47082971bbdc6d5162cc80170f06bf5a` (rustc 1.96.0, `stellar-cli` 27.0.0), admin `GBPLRG4TQSCCJEVO7IZZXTRXWMQBSUJWWX6SZTSVPGSXVEX3PVOTBHP5`, deployed 2026-10-09 |

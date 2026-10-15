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
| Embeds | `perch-account` `d3d4c28a01b37660c23ac03622b712608d2c0f853b634a597f3cd617e7b66df5`, Perch `845c49a`'s release ([below](#perch-845c49a-the-stack-the-factorys-accounts-use)), not the pinned manifest's `accountWasmHash` |
| Verifier pin | `CAL7IEAJO7S3SJI4EXESMUNPOEYW6QNR3PQTO7AVHD75YGURSZ5CW27Z`, Perch `845c49a`'s `perch-webauthn-verifier` (`set_registry_pins`), not the pinned manifest's |
| Admin | `GA2MQ7MBJQCIHGO3ROH7254A5MUNW34UWFHOT4Y2ZPZIHOLEBF57C22Q`, a single throwaway testnet deploy key |
| Deployed | 2026-10-12 (nidohq/nido#255), with the pin and the account hash the factory deploys read back |
| Registry name | None |

**This factory predates the pinned Perch release.** The re-pin to Perch
`cb17149` (nidohq/nido#267) did not redeploy it, so every account it creates
runs Perch `845c49a`'s account code and names that release's verifier, while
`perch.TESTNET` names the `cb17149` release. Redeploying the factory against
the pinned manifest (RUNBOOKS §2.2) and recording it here closes the gap.

### Perch 845c49a: the stack the factory's accounts use

The account wasm the factory embeds pins this release's doc compiler,
interpreter, and spending limit at build time, and the factory pins its
WebAuthn verifier. Values from Perch `845c49a`'s `deployments/testnet.json`
(the "before" column of nidohq/nido#267).

| Contract | Address | Wasm sha256 |
| --- | --- | --- |
| Perch registry instance | `CAR2DSSOBJB76GGD6MAAKWUK36Y7I7O3NDWTN7HTIRV5I3XZ27U3ZBVZ` | |
| `perch-account` (installed) | | `d3d4c28a01b37660c23ac03622b712608d2c0f853b634a597f3cd617e7b66df5` |
| `perch-webauthn-verifier` | `CAL7IEAJO7S3SJI4EXESMUNPOEYW6QNR3PQTO7AVHD75YGURSZ5CW27Z` | `9e9fbe7886d9bb149a6e3ee10de15954c57bbdf20f817ed94e1370c01b9c669e` |
| `perch-doc-compiler` | `CCYSZHRHY7GKT2OYXF6JW332GA2BL6ZKPAWIV6RVC5JW2RNPHQPSW5ZI` | `ccea12cd4b2f23d9bce07e3d9d3aaf93c43df79416b22a8c9a122d467b707853` |
| `perch-interpreter` | `CA5JLPEVA3E5X7YEDVABMEM3TML33ZS3I6WL5NDBFIZZAXFYNZPBBWTO` | `2254f17dd722e5113caee901be96849c13e5a6853a6213d62473abe637ae33e1` |
| `perch-spending-limit` | `CD3FGRDBG7L5KNJAOQZW5WWKK4E5CQ63DNC3W25B63WEIGYX25NQDN4K` | `f2f0560ce501ab59144ed71a10349b30bcefaf344ca121c0bd9841577b83c2b7` |

## Nido contracts in use

| Name | Address | Notes |
| --- | --- | --- |
| Name registry | `CDVVRZAVXTUQLS5LCGUP3H26RGOIUFKNE2UEJ6CAWYMBWY5LNORF6POX` | Account names. Read by `infra/nido-resolver` and by the wallet, which resolves it as `name-registry` through the Stellar Registry with this address as the fallback. |
| Status message (demo) | `CD5FK6CQ7QIZ5ONARG36Y53ERI5PIBGELSJUTD7OXYLK6EQAS4N3TFBV` | Used by the example dApp. |

## External contracts

| Name | Address | Notes |
| --- | --- | --- |
| Stellar Registry (unverified) | `CDBL7MNO7UI5OAAIC67UIWKQ4P3S6RVQSFCQXUHUW6TOFCXSYRPNHY4S` | External (AhaLabs). The wallet resolves `name-registry`, `status-message`, and `spending-limit-policy` through it at runtime (`packages/passkey-sdk/src/registry.ts`, with hardcoded fallbacks for some names). The factory's `REGISTRY` constant, consulted only for an unpinned verifier; the factory above is pinned. |

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
| Factory (Perch, first testnet release) | `CBFDM3GWAYW4BFGRGDS45OKLU6BWPEKMOY6U6T3JD5E35FDDWITS4VOE` | Wasm `4a16b51b…`, built from Nido `42738a3`. Embeds `perch-account` `bbb30174…` and pins the WebAuthn verifier `CBCCINHRMS3COAV5RHTCUASZLOEC52FCOBR3HMU4FKWJTAHWZTVFTHHY`; admin `GBPLRG4TQSCCJEVO7IZZXTRXWMQBSUJWWX6SZTSVPGSXVEX3PVOTBHP5`, a throwaway key. Its accounts pin that release's doc compiler `CDHZT7NLQDPMWCUDNUVCYC2EAMGRFWABQO5WDSRJGDQVIDHOWQB2FANB`, interpreter `CAI6RPWAJ7Z6MP3HLGMTD3W4P4DTD6BEKPFV7XF6VANC2H7XYAQHIXHP`, and spending limit `CCVXXCAKMROSWAH6QKZ2PUMMH3QUUEUERJQ3CI4XMAWVOMTKKJHYSMTF` under registry `CCUC5RDRGRFFC5VGG7HCB3OMNNSYDFAQOSA7SBGYUM2GDXAJBUWI5TFQ`, and verify the earlier `oz_rule_ids` digest, without the account-address binding (the integration suite's `old-perch-account.wasm`). The wallet no longer targets it. |
| Factory (doc-only) | `CCJFOM6UGOH7JSAX22C3FAECG5657HKIUYDBTCMUMILKDA6LOA2J2EGG` | Embeds Nido's former smart account (wasm `fe3b1878…`). Still the registry's `factory` name and the SDK's `factory` fallback; the wallet uses it only when built without a Perch deployment (`fetchFactoryAddress`). Repointing the name is a separate, deliberate step (RUNBOOKS §2.2). |
| WebAuthn verifier (Nido's former) | `CACVGSAHYFBXY4LJKWW5B57LAAXHCZVDZOANUTYPLNV6HHQI4Q35EGMY` | Admin-upgradeable; its source is not in this tree. Registered as `verifier` and the SDK's `verifier` fallback. Every account a pre-Perch Nido factory minted names it, so its admin key remains a trust anchor for those accounts (THREAT_MODEL 7). The wallet falls back to it only when it cannot read an account's admin rule and has no Perch deployment (`fetchVerifierAddress`). |
| Multisig policy (pre-Perch) | `CCSDKJYOFCPTCCGQZPF73RJNHFC7TPO532Q36N3M2VBYZFWQOTDB7J7G` | `contracts/multisig-policy`. A Perch document can't attach it, so only accounts minted by pre-Perch factories can carry it. |
| Spending-limit policy (pre-Perch) | `CCJMCPGADKMVKYOIZXMV7UWH62XYDAIT6GJRNJPQSZ2CHPOF4K2AU2QC` | `contracts/spending-limit-policy`. A Perch document can't attach it. The wallet resolves the registry's `spending-limit-policy` to show the cap of a rule that carries it (`fetchSpendingLimit`), and to decompile documents when built without a Perch deployment. |

### Perch policy layer (0.2.1 era)

The doc compiler 0.2.1 and interpreter that registry `CDX2DMYM…`
content-addressed before Perch `cb17149` deployed its current ones under the
same registry (the manifest table above). Each address derives offline from
the registry id and the wasm hash. Nothing in this tree derives or targets
them now: `perchTestnetAddresses()` in
`packages/passkey-sdk/src/policyDoc/deployment.ts` derives the pinned
manifest's compiler and interpreter. Current accounts do not pin them.

| Name | Address | Notes |
| --- | --- | --- |
| Perch stateless registry | `CDX2DMYMMEYU6FGN3HPJ2GQSSL5EZHIAMEJD4SPF55FZE5LEUBPPPDA7` | Doc-compiler 0.2.1 generation, and the pinned manifest's registry too. |
| Perch doc compiler 0.2.1 | `CDWBJPDMBORIZERIFVMTGJFND6ZTAQJIVDNYST4SV33YBQP47BPKOHR6` | Wasm `35f248f0…`. |
| Perch interpreter | `CDR2OTZIZYTAHEHHH5MBOL6RKLWKIEN5KLPIVOG7FVBVTFET552NTWL2` | Wasm `f63cae53…`. |

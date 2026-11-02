# Sender authentication per launch provider (assumption A1b)

The circuit proves that a provider's DKIM key signed a header block whose
single signed `from` field names an address (spec §4.3, §4.5). That the
address is the user's rests on two assumptions (spec §11.1):

- **A1a, unforgeability.** Nobody without the provider's private key can
  produce a valid RSA-2048 signature under it.
- **A1b, sender authentication.** The provider signs a `from` field naming
  one of its mailboxes only when that mailbox's holder submitted the
  message. For the circuit's reading this needs, per provider:
  1. a submission with two `From` fields is refused or rewritten, or the
     provider authenticates the instance it signs (the bottom-most one when
     `h=` names `from` once, RFC 6376 §5.4.2), and a `From` value naming
     several addresses is refused, or the provider authenticates the
     address the circuit binds (the angle-addr that ends the field, §4.5);
  2. sending as another address of the provider's own domain requires
     proof of control of that mailbox;
  3. an address is not reassigned to someone else, or, if it is, the new
     holder cannot use it against an account enrolled by the old one.

Condition 3 is mitigated by the design: the commitment `C` binds the address
together with the user's `account_code` (spec §5.1, §5.3), which a later
holder of a reassigned address does not have. Conditions 1 and 2 have no such
mitigation.

This is a review of public documentation and publicly reported
measurements, read on 2026-11-02; nothing here was tested against a real
provider. Each cell gives its source, or says what is unknown and what would
establish it. The two measurement studies are:

- **[Chen20]** J. Chen, V. Paxson, J. Jiang, "Composition Kills: A Case
  Study of Email Sender Authentication", USENIX Security 2020,
  <https://www.usenix.org/system/files/sec20-chen-jianjun.pdf>. §6.2 tested
  eight providers' submission paths with a custom client; §7 gives the
  providers' responses.
- **[Shen21]** K. Shen et al., "Weak Links in Authentication Chains: A
  Large-scale Analysis of Email Sender Spoofing Attacks", USENIX Security
  2021, <https://www.usenix.org/system/files/sec21-shen-kaiwen.pdf>. Table 1
  (sending stage), §4.1 and §6 (Figure 14).

Both are several years old and the providers responded to them; they show
what each submission path did then, not what it does now.

The `h=` column is the signed-header list of each provider's own signature as
observed in public archives (`packages/email-mocks/PROVIDERS.md`). Where `h=`
names `from` more often than it occurs, a second `From` field lands in the
signed block and the circuit refuses it (§4.3 rule 6), whatever the provider
authenticated.

| Provider | `h=` and `from` | 1. Two `From` fields, several addresses | 2. Sending as another in-domain address | 3. Reassignment of addresses |
| --- | --- | --- | --- | --- |
| Gmail (gmail.com) | oversigned (`from` listed twice) | [Chen20] §6.2: Gmail's submission accepted `From:admin@a.com\,<user@a.com>` and checked only the second address, the angle-addr the circuit binds; §7: Gmail fixed A18 (a Gmail-signed message replayed with an added `From` field). [Shen21] Table 1 lists no sending-stage weakness for Gmail. Two `From` fields at submission today: **unknown** | Requires clicking a confirmation link sent to that address: Gmail Help, "Send emails from a different address or alias", <https://support.google.com/mail/answer/22370> | Not reassigned: "Your Gmail address can't be used by anyone in the future." Google Account Help, "Remove Gmail from your Google Account", <https://support.google.com/accounts/answer/61177> |
| Outlook.com, Hotmail (outlook.com, hotmail.com) | listed once | [Chen20] §6.2: the only one of eight providers whose submission validated `From` strictly. [Shen21] Table 1 marks a sending-stage weakness (A2, `MAIL FROM` and `From` differing) and §4.1 says Outlook refused that but that multiple-`From` and multiple-address variants bypassed such checks, without per-provider detail. Today: **unknown** | In-domain aliases are new outlook.com addresses created on the account: Microsoft Support, "How to add an email address to your Microsoft account", <https://support.microsoft.com/en-us/office/add-or-remove-an-email-alias-in-outlook-com-459b1989-356d-40fa-a689-8f285b13f1f2>. Sending as another user's existing mailbox: **unknown** (not documented) | Not reassigned. Microsoft Support, "How to create a new Microsoft account", Important note, as written: "Addresses used for Microsoft accounts cannot be not reused", <https://support.microsoft.com/en-us/accounts-billing/manage/how-to-create-a-new-microsoft-account> |
| iCloud Mail (icloud.com) | listed once | [Chen20] §6.2: "iCloud.com (Server) … accept[s] multiple From headers and only check[s] if the first one matches with the authenticated username" and accepts multiple addresses, checking only the first; §7: Apple said it was fixing these. With `from` listed once, the signed instance is the bottom-most, so that behaviour would let one iCloud user obtain a signature the circuit reads as another's. Today: **unknown** | Up to three @icloud.com aliases created for the account: Apple Support, "What are email aliases in iCloud Mail?", <https://support.apple.com/guide/icloud/what-are-email-aliases-in-icloud-mail-mm074af79454/icloud>. Sending as another existing mailbox: **unknown** | **Unknown**: Apple's alias page says a deleted alias's slot reopens after 7 days but not whether the address can be registered by someone else |
| Yahoo Mail (yahoo.com) | oversigned | [Chen20] §6.2: accepted several addresses in `From` and checked only the first. [Shen21] §6, Figure 14: refused a `From` differing from `MAIL FROM`, but accepted a second `From` header after a first one that matched. Because `from` is oversigned, two `From` fields are refused by the circuit; a `From` listing two addresses is not (see the parser finding in [README.md](README.md)). Today: **unknown** | Send-only addresses are verified by a message sent to them: Yahoo Help SLN36683, "Add, delete, or edit a send-only address in New Yahoo Mail", <https://help.yahoo.com/kb/SLN36683.html>; disposable addresses are `nickname-keyword@yahoo.com` of the account: SLN36718, <https://help.yahoo.com/kb/SLN36718.html> | Inactive IDs were released to other users in 2013: NBC News, "Yahoo accepting requests for inactive email IDs", 2013-07-16, <https://www.nbcnews.com/technolog/yahoo-accepting-requests-inactive-email-ids-6c10648550>. Today an account is deleted after 18 months without sign-in (Yahoo Help, "Reasons Yahoo deactivates or deletes an account", <https://uk.help.yahoo.com/kb/account/inactive-sln3057.html>); whether the ID is then released: **unknown** |
| Proton Mail (proton.me, protonmail.com) | oversigned | Not tested by either study ([Chen20] §6.2 note 4 and [Shen21] §3.2: no third-party client access for the test accounts). **Unknown** | Additional addresses are created on the account: Proton Support, "Email addresses and aliases", <https://proton.me/support/addresses-and-aliases>. Sending as another user's mailbox: not offered there | Not reassigned: "We don't recycle usernames. If you delete your account, your username can't be used by someone else", Proton Support, "How to delete your Proton Account", <https://proton.me/support/delete-account> |
| Fastmail (fastmail.com) | oversigned | [Chen20] §6.2: "Fastmail.com (Server) accepts arbitrary email addresses in the From header, even email addresses from different domains"; §7: Fastmail rewarded the report. Today: **unknown** | A sending identity must be verified with a code received at that address: Fastmail Help, "Identities", <https://www.fastmail.help/hc/en-us/articles/1500000280401-Identities> | **Reassigned**: "Once an account has been deleted, the username and any addresses on the account can be re-used." Fastmail Help, "Canceling and deleting accounts", <https://www.fastmail.help/hc/en-us/articles/1500000277342-Canceling-and-deleting-accounts>. Mitigated by `account_code` |
| GMX, WEB.DE (gmx.net, gmx.de, web.de) | oversigned | Not tested by either study ([Shen21] §3.2 could not register gmx.com). **Unknown** | New GMX addresses and aliases are created after an availability check ("Es wird überprüft, ob diese E-Mail-Adresse zur Verfügung steht"): GMX Hilfe, "E-Mail-Adressen verwalten", <https://hilfe.gmx.net/email/einstellungen/emailadressen-verwalten.html>. Sending as another user's mailbox: **unknown** | **Reassigned** for free accounts after one year of inactivity: GMX AGB 5.3, "… ist GMX darüber hinaus berechtigt, die vom Nutzer bei GMX registrierten E-Mail-Adressen freizugeben und anderen Nutzern zur Verfügung zu stellen", <https://agb-server.gmx.net/gmxagb-de>; the same clause in the WEB.DE AGB, <https://agb-server.web.de/webdeagb>. Mitigated by `account_code` |

## What would settle the unknowns

Every **unknown** in column 1 is a property of a provider's submission
path today. A controlled test settles it: from test accounts at each
provider, submit (through the web client and, where offered, SMTP
submission or the provider's bridge) messages with (a) two `From` fields
naming the account and another in-domain address in both orders, (b) one
`From` naming both addresses, as a list and as `address <address>`, and
(c) a display name holding an address; record whether the provider
refuses, rewrites, or signs, and which `from` instance its `DKIM-Signature`
covers. That test sends real mail through real providers, which this
repository does not do (every provider here is a mock); it needs test
accounts and a decision to run it. The column-2 and column-3 unknowns need
the provider's own statement. Spec §13 lists them as open questions.

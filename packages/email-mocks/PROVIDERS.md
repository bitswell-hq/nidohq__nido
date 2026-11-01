# Provider signing formats

What each launch provider's outbound DKIM signature and header block look
like, the public source for each observation, and what the mock does where a
field could not be established. Every key and message the mock produces is
TEST-ONLY; no real provider key is used or derived.

## How these were established

- **Header order, tag order, `h=` lists, `t=`/`x=`, selectors, From, Date,
  Message-ID and MIME shapes**: read from the raw headers of public
  mailing-list posts in the GNU Mailman mbox archives
  (`https://lists.gnu.org/archive/mbox/<list>/<YYYY-MM>`, ten lists, June to
  October 2026). Each row cites the archive month and the post's Message-ID.
  Mailman 2.1 rewrites header continuation whitespace, so these copies were
  not used for folding.
- **Byte-exact folding of the signature fields**: read from the same
  providers' posts as served by Gmane over NNTP (`nntp://news.gmane.io/...`),
  whose list paths do not refold headers. The 28 observed signatures are in
  [`test/observed-signature-layouts.json`](test/observed-signature-layouts.json)
  (tag order, `d=`, `s=`, `h=`, physical line lengths, source), and
  `test/layouts.test.ts` replays each through the mock's layout and requires
  the same line breaks. All 28 match.
- **DNS key records**: `dig +short TXT <selector>._domainkey.<domain>` against
  the live DNS on 2026-11-01, with each `p=` decoded by
  `openssl pkey -pubin -inform DER -text -noout`. Every live key of every
  launch provider is RSA-2048. Whether sibling domains share a key was
  checked by comparing the published `p=` values.
- **Fastmail's wrapping algorithm**: read from the source of Perl
  Mail::DKIM 1.20240923 (`Mail::DKIM::TextWrap`,
  `Mail::DKIM::KeyValueList::wrap`, `Mail::DKIM::Signature::prettify` and
  `prettify_safe`, `Mail::DKIM::Algorithm::Base::finish_message`,
  `Mail::DKIM::Signer`), <https://metacpan.org/release/MBRADSHAW/Mail-DKIM-1.20240923>.
  The port in `src/layout.ts` reproduces all six observed Fastmail
  signatures.
- **Signing and canonicalization rules**: RFC 6376
  (<https://www.rfc-editor.org/rfc/rfc6376>) sections 3.4 (canonicalization),
  3.5 (tags), 3.6.1 (key records, empty `p=` is revoked), 3.7 (the signed
  data), 5.4.2 (bottom-up header selection and oversigning), 6.1.1 (From must
  be signed); RFC 8301 (<https://www.rfc-editor.org/rfc/rfc8301>) for
  rsa-sha256 and key sizes. RFC 8463 (Ed25519) is not used by any launch
  provider: every observed signature is `a=rsa-sha256`.
- No private mail was used. The fixture tables below give shapes, not anyone's
  name or address; Message-IDs are cited because they identify the public
  post.

All rows were checked on **2026-11-01**.

## Common to all launch providers

| Provider | Field | Observed value | Source | Checked |
|---|---|---|---|---|
| all | `v` / `a` / `c` | `v=1`, `a=rsa-sha256`, `c=relaxed/relaxed` | every sample below | 2026-11-01 |
| all | `l=` / `q=` | never present | every sample below | 2026-11-01 |
| all | `bh=` / `b=` | 44 / 344 base64 characters (SHA-256, RSA-2048) | every sample below | 2026-11-01 |
| all | key size | RSA-2048, e = 65537, for every live selector | live DNS, decoded with OpenSSL | 2026-11-01 |
| all | `d=` alignment | the provider's own signature has `d=` equal to the From domain | every sample below | 2026-11-01 |
| all | line endings | CRLF | RFC 5322 section 2.1; the archives store LF, the wire form is CRLF | 2026-11-01 |

## Gmail (gmail.com, googlemail.com)

The mock models a new message from the web client in plain-text mode.

| Provider | Field | Observed value | Source | Checked |
|---|---|---|---|---|
| Gmail | signatures | two: `DKIM-Signature` `d=gmail.com`, then directly below it `X-Google-DKIM-Signature` `d=1e100.net` (a field name verifiers do not read) | <https://lists.gnu.org/archive/mbox/bug-bash/2026-10> `<CAGiELgqdhNdRa+Y4m1ZH2Kik2L93=Jq=mSz7n_bg5m_hcPR6JQ@mail.gmail.com>` | 2026-11-01 |
| Gmail | tag order | `v a c d s t x darn h bh b`; X-Google: `v a c d s t x h bh b` | <https://lists.gnu.org/archive/mbox/bug-bash/2026-06> `<CAA91j0XAC=ebbPTJbgNPM0N=Op_-GHmbT3JeRUqbXh7Vu-4Lgw@mail.gmail.com>` | 2026-11-01 |
| Gmail | `t=` / `x=` | both; `x - t` = 604800 (7 days) | same | 2026-11-01 |
| Gmail | `darn=` | nonstandard tag carrying the recipient domain, between `x=` and `h=` | same | 2026-11-01 |
| Gmail | selector | `20260707` (from 2026-10-27); `20251104` before, still published live | <https://lists.gnu.org/archive/mbox/bug-bash/2026-10> `<CAGiELgqdhNdRa+Y4m1ZH2Kik2L93=Jq=mSz7n_bg5m_hcPR6JQ@mail.gmail.com>`; live DNS | 2026-11-01 |
| Gmail | `h=` | signed headers present, listed bottom-up, then the oversigned tail `from:to:cc:subject:date:message-id:reply-to:content-type`; new plain message: `content-type:to:subject:message-id:date:from:mime-version:from:to:cc:subject:date:message-id:reply-to:content-type`. X-Google inserts `x-gm-gg:x-gm-message-state` before the tail | same | 2026-11-01 |
| Gmail | folding | line 1 `v a c`; 8-space indent; `d s t x darn` on one line (may pass 78 columns); `h=` broken before `:` with 9-space continuation at 77 columns; `b=` cut into 68-character pieces counting `b=` | `nntp://news.gmane.io/gmane.comp.version-control.git/563642` `<CAKrRMNoAALZ0V5fdKjZPQnCXuMP8y49vfUmxYnRt7UEeUTE7kA@mail.gmail.com>` | 2026-11-01 |
| Gmail | header order (web) | Received / [ARC set] / DKIM-Signature / X-Google-DKIM-Signature / X-Gm-Message-State / X-Gm-Gg / X-Received / MIME-Version / From / Date / X-Gm-Features / Message-ID / Subject / To / Content-Type / [Content-Transfer-Encoding] | <https://lists.gnu.org/archive/mbox/emacs-devel/2026-08> `<CA+TD5hgByro0+roP1wZwopXUnsdMYfhCXeoB4Bh8_UWg7MOYdw@mail.gmail.com>` | 2026-11-01 |
| Gmail | From | `Display Name <local@gmail.com>`, name unquoted when it is an atom sequence; bare addr-spec without a name | <https://lists.gnu.org/archive/mbox/bug-bash/2026-06> `<CAA91j0XAC=ebbPTJbgNPM0N=Op_-GHmbT3JeRUqbXh7Vu-4Lgw@mail.gmail.com>` | 2026-11-01 |
| Gmail | Date | `Mon, 1 Jun 2026 11:08:49 +0300`: day not zero-padded, sender's local offset, no comment | same | 2026-11-01 |
| Gmail | Message-ID | `<CA` + 49 characters of `[A-Za-z0-9+_=-]` + `@mail.gmail.com>` | same | 2026-11-01 |
| Gmail | MIME (plain-text mode) | `Content-Type: text/plain; charset="UTF-8"`, quoted-printable only when needed | <https://lists.gnu.org/archive/mbox/emacs-devel/2026-08> `<CA+TD5hgByro0+roP1wZwopXUnsdMYfhCXeoB4Bh8_UWg7MOYdw@mail.gmail.com>` | 2026-11-01 |
| Gmail | DNS | `v=DKIM1; k=rsa; p=...` at `20260707` and `20251104` on gmail.com, googlemail.com and 1e100.net; gmail.com and googlemail.com publish the same key; `20230601`, `20221208`, `20210112` publish `v=DKIM1; k=rsa; p=` (revoked) | live DNS | 2026-11-01 |

Not established, and what the mock does:

- No googlemail.com post was found. The mock signs googlemail.com mail as
  Gmail signs gmail.com mail, with `d=googlemail.com` and the shared key the
  DNS shows.
- Gmail's default compose mode sends `multipart/alternative` (text/plain and
  text/html). The mock models plain-text mode only.
- The ARC set Gmail's web path adds above the signatures is not modeled.
  Opaque fields (X-Gm-*, X-Received) are random values of the observed shape.
- Whether Gmail folds a Subject longer than 78 characters was not observed;
  the mock writes the Subject on one line (RFC 5322 section 2.1.1 allows up to
  998).

## Outlook.com / Hotmail (outlook.com, hotmail.com)

The mock models a new plain-text message from Outlook on the web.

| Provider | Field | Observed value | Source | Checked |
|---|---|---|---|---|
| Outlook | signatures | one `DKIM-Signature`, `d=` the From domain; an ARC set from microsoft.com above it | <https://lists.gnu.org/archive/mbox/emacs-devel/2026-08> `<PA3P191MB29839629B5D60E2B0710D3B483A22@PA3P191MB2983.EURP191.PROD.OUTLOOK.COM>` | 2026-11-01 |
| Outlook | tag order | `v a c d s h bh b` | same | 2026-11-01 |
| Outlook | `t=` / `x=` | **neither** | same | 2026-11-01 |
| Outlook | selector | `selector1` | same; live DNS | 2026-11-01 |
| Outlook | `h=` | fixed, in this case: `From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-SenderADCheck`; the last name never occurs, so it signs its absence; To and Cc are not signed; From and Subject are listed once (not oversigned) | same | 2026-11-01 |
| Outlook | folding | one-space indent; tags before `h=` packed onto lines of at most 78 characters; `h=`, `bh=` and `b=` each on one unbroken line | `nntp://news.gmane.io/gmane.linux.debian.devel.general/263182` `<PUZPR04MB638211C637006DE0BE23C06CD36B2__38715.6410653674$1793495256$gmane$org@PUZPR04MB6382.apcprd04.prod.outlook.com>` | 2026-11-01 |
| Outlook | header order (Outlook-native) | [ARC set] / DKIM-Signature / Received x2 (Exchange) / From / To / Subject / Thread-Topic / Thread-Index / Date / Message-ID / Accept-Language / Content-Language / X-MS-Has-Attach / X-MS-TNEF-Correlator / lower-case x-ms-* block / Content-Type / [Content-Transfer-Encoding] / MIME-Version / X-OriginatorOrg / X-MS-Exchange-CrossTenant-* | <https://lists.gnu.org/archive/mbox/emacs-devel/2026-08> `<PA3P191MB29839629B5D60E2B0710D3B483A22@PA3P191MB2983.EURP191.PROD.OUTLOOK.COM>` | 2026-11-01 |
| Outlook | Date | `Sat, 24 Oct 2026 14:51:56 +0000`: always `+0000`, day not padded | <https://lists.gnu.org/archive/mbox/emacs-orgmode/2026-10> `<7B101EB4-A3E3-4B0C-9BDD-DA3F7DB632CC@hotmail.com>` | 2026-11-01 |
| Outlook | Message-ID | `<{mailbox server}{hex}@{mailbox server}.{region}.prod.outlook.com>` | `nntp://news.gmane.io/gmane.linux.debian.devel.general/263182` (above) | 2026-11-01 |
| Outlook | Content-Type | Outlook-native plain text: `text/plain; charset="iso-8859-1"` or `"us-ascii"` with quoted-printable, or `"utf-8"`/other charsets with base64; the default (HTML) composer sends `multipart/alternative` (23 of the 49 Outlook-native posts) | <https://lists.gnu.org/archive/mbox/bug-gnu-emacs/2026-06> `<TYCPR01MB10004F1D888BE64F33BA3DC85FBE32@TYCPR01MB10004.jpnprd01.prod.outlook.com>`; <https://lists.gnu.org/archive/mbox/bug-gnu-emacs/2026-08> `<DBBBD9D0-D70D-4BE6-968C-799516E6B17F@hotmail.com>` | 2026-11-01 |
| Outlook | DNS | CNAME to `selectorN._domainkey.outbound.protection.outlook.com`, TXT `v=DKIM1;k=rsa;p=...;n=2048,1452627113,1468351913` (no spaces); outlook.com and hotmail.com resolve to the same key | live DNS | 2026-11-01 |

Not established, and what the mock does:

- The mock DNS serves the TXT directly at the selector name; the CNAME hop is
  not modeled.
- The mock sends plain text as `text/plain; charset="us-ascii"` (or
  `"utf-8"` for non-ASCII text) with quoted-printable, not the default
  `multipart/alternative`.
- The ARC set is not modeled; X-MS-* values are random values of the observed
  shape.

## iCloud Mail (icloud.com, me.com)

The mock models a new plain-text message from Apple Mail on macOS.

| Provider | Field | Observed value | Source | Checked |
|---|---|---|---|---|
| iCloud | signatures | one, field name spelled `Dkim-Signature` | <https://lists.gnu.org/archive/mbox/emacs-orgmode/2026-07> `<8824AC80-AD7F-4B03-869A-F3B3A57BD6E8@icloud.com>` | 2026-11-01 |
| iCloud | tag order | `v a c d s t x bh h b` | same | 2026-11-01 |
| iCloud | `t=` / `x=` | both; `x - t` = 31536000 (365 days) from 2026-10-08 (30 days before 2026-10-02) | <https://lists.gnu.org/archive/mbox/emacs-devel/2026-10> `<71034C0E-45FB-4A65-8195-37BF0BA71DA6@mac.com>` | 2026-11-01 |
| iCloud | selector | `1a1hai` on every iCloud domain | same; live DNS | 2026-11-01 |
| iCloud | `h=` | signed headers present from {From, To, Subject, Date, Message-ID, MIME-Version, Content-Type}, in message order and the client's capitalisation, then `x-icloud-hme` (absent, so signs its absence). Apple Mail: `From:Content-Type:Mime-Version:Subject:Message-Id:Date:To:x-icloud-hme`. Not oversigned | <https://lists.gnu.org/archive/mbox/emacs-orgmode/2026-07> `<8824AC80-AD7F-4B03-869A-F3B3A57BD6E8@icloud.com>` | 2026-11-01 |
| iCloud | folding | one unfolded line of about 570 characters | `nntp://news.gmane.io/gmane.comp.version-control.git/561038` `<79ae606b-cf99-4867-9db3-bcd7ff03626d@icloud.com>` | 2026-11-01 |
| iCloud | header order | Received (outbound) / X-ICL-Out-Info / Dkim-Signature / Received (from the client) / client headers / X-Proofpoint-* | <https://lists.gnu.org/archive/mbox/emacs-orgmode/2026-06> `<87cxxovldi.fsf@icloud.com>` | 2026-11-01 |
| iCloud | Apple Mail headers | From / Content-Type (`text/plain;` folded, `charset=utf-8`) / Content-Transfer-Encoding / Mime-Version `1.0 (Mac OS X Mail 16.0 \(3826.400.131.1.6\))` / Subject / Message-Id `<UPPER-CASE-UUID@icloud.com>` / Date (local offset, day not padded) / To / X-Mailer | <https://lists.gnu.org/archive/mbox/emacs-orgmode/2026-07> `<8824AC80-AD7F-4B03-869A-F3B3A57BD6E8@icloud.com>` | 2026-11-01 |
| iCloud | DNS | `v=DKIM1; k=rsa; p=...`; icloud.com and me.com publish **different** keys | live DNS | 2026-11-01 |
| iCloud | Subject (web client) | the iCloud web client sent a pure-ASCII Subject (93 characters, containing a double space) as three RFC 2047 `=?utf-8?B?...?=` encoded-words folded over three lines; the `d=me.com` signature, which covers Subject, verifies over those octets (mailauth 8.0.4, live DNS), so the encoding is iCloud's and not the list's | <https://lists.gnu.org/archive/mbox/emacs-orgmode/2026-06> `<f5ba8f4b-e927-4b48-bef3-953098799ff6@me.com>` | 2026-11-01 |

Not established, and what the mock does: iCloud's web client and iPhone Mail
use other header orders and Message-ID forms (`Message-id: <lower-case-uuid@me.com>` from the web client); the
mock models Apple Mail only. Proofpoint and X-ICL values are random values of
the observed shape.

## Yahoo Mail (yahoo.com)

The mock models a new message from the web client.

| Provider | Field | Observed value | Source | Checked |
|---|---|---|---|---|
| Yahoo | signatures | `DKIM-Signature`, then directly below an internal `X-SONIC-DKIM-SIGN` with the same key (`h=X-Sonic-MF:...:From:Subject`) | <https://lists.gnu.org/archive/mbox/help-gnu-emacs/2026-09> `<1445064262.511730.1789690934205@mail.yahoo.com>` | 2026-11-01 |
| Yahoo | tag order | `v a c d s t bh h b` | same | 2026-11-01 |
| Yahoo | `t=` / `x=` | `t=` only, **no `x=`** | same | 2026-11-01 |
| Yahoo | selector | `s2048` | same; live DNS | 2026-11-01 |
| Yahoo | `h=` | signed headers present from {Date, From, Reply-To, To, Cc, Subject, References, In-Reply-To} in message order, then `From:Subject:Reply-To`; web: `Date:From:To:References:Subject:From:Subject:Reply-To`. Message-ID, MIME-Version and Content-Type are not signed | same | 2026-11-01 |
| Yahoo | folding | one unfolded line of about 550 characters | `nntp://news.gmane.io/gmane.linux.debian.devel.general/262469` `<1325370483.1274657.1788087894170@mail.yahoo.com>` | 2026-11-01 |
| Yahoo | header order (web) | DKIM-Signature / X-SONIC-DKIM-SIGN / X-YMail-OSG / X-Sonic-MF / X-Sonic-ID / Received (HTTP) / Date / From / To / Message-ID / References / Subject / MIME-Version / [Content-Type] / X-Mailer / Content-Length | <https://lists.gnu.org/archive/mbox/help-gnu-emacs/2026-09> `<1445064262.511730.1789690934205@mail.yahoo.com>` | 2026-11-01 |
| Yahoo | Message-ID / References | `<{10 digits}.{6-7 digits}.{13-digit ms}@mail.yahoo.com>`; Yahoo adds `References:` with the same ID and `.ref` before the `@` | same | 2026-11-01 |
| Yahoo | Date | `Fri, 18 Sep 2026 00:22:14 +0000 (UTC)` | same | 2026-11-01 |
| Yahoo | DNS | `k=rsa; p=...;` (no `v=`, trailing `;`) | live DNS | 2026-11-01 |

Not established, and what the mock does: Mailman rewrote the web posts'
Content-Type, so the mock uses `text/plain; charset=UTF-8` with `7bit` (or
quoted-printable) following RFC 2045/2046. Whether Yahoo pads single-digit
days was not observed; the mock does not pad. Coverage is about three
distinct senders.

## Proton Mail (proton.me, protonmail.com)

The mock models a new plain-text message from the web client.

| Provider | Field | Observed value | Source | Checked |
|---|---|---|---|---|
| Proton | signatures | one | <https://lists.gnu.org/archive/mbox/bug-bash/2026-07> `<3A_yI8xWnOh1mVk3zUotb4UJ1y-HyrxbyG8Rnch0oJatXegLGlcB8pMUGhWk53Q0ShZCDYC72yoxAveqmfsy988e6UUz7CF-heYNDjAhyP0=@proton.me>` | 2026-11-01 |
| Proton | tag order | `v a c d s t x bh h b` | same | 2026-11-01 |
| Proton | `t=` / `x=` | both; `x - t` = 259200 (3 days) | same | 2026-11-01 |
| Proton | selector | proton.me: `protonmail2` (from September 2026); protonmail.com: `protonmail3` | <https://lists.gnu.org/archive/mbox/bug-bash/2026-09> `<iYNVv7Ct8MZV4UdjXEohp6HqfB-Rsf242JnqU7xh2PUukxXs4Kjq2MIFj6w-G8OfLlKQVcxy6sfgDlLm0zHoy3nA3jYO0MEk_ziz20qRlCM=@proton.me>`; live DNS | 2026-11-01 |
| Proton | `h=` | signed headers present from {Date, To, From, Cc, Subject, Message-ID, In-Reply-To, References, Feedback-ID} in message order, then the oversigned tail `From:To:Cc:Date:Subject:Reply-To:Feedback-ID:Message-ID:BIMI-Selector`; MIME-Version and Content-Type not signed | <https://lists.gnu.org/archive/mbox/bug-bash/2026-07> (above) | 2026-11-01 |
| Proton | folding | line 1 `v a c d`; TAB-indented `s t x`, `bh`, `h`, `b` lines; `h=` broken after `:` and `b=` filled to 68 columns, both continued with TAB SP | `nntp://news.gmane.io/gmane.linux.debian.devel.general/263156` `<f79f991f3d1f3dc69eb4a6534206a156__23268.6247372598$1793349254$gmane$org@proton.me>` | 2026-11-01 |
| Proton | header order | DKIM-Signature (first; internal Received fields are stripped) / Date / To / From / Subject / Message-ID / Feedback-ID / X-Pm-Message-ID / MIME-Version / Content-Type / Content-Transfer-Encoding | <https://lists.gnu.org/archive/mbox/bug-bash/2026-09> (above) | 2026-11-01 |
| Proton | shapes | From `"Quoted Name" <addr>` when the name needs quoting; Date `Mon, 03 Aug 2026 22:39:52 +0000` (padded, always `+0000`); Message-ID `<` 107 base64url characters `=@<domain>>`; `text/plain; charset=utf-8`, quoted-printable; Feedback-ID `<digits>:user:proton` | <https://lists.gnu.org/archive/mbox/bug-bash/2026-07> (above) | 2026-11-01 |
| Proton | DNS | `v=DKIM1; k=rsa; p=...`; proton.me (via CNAME to `*.domains.proton.ch`) and protonmail.com publish **different** keys | live DNS | 2026-11-01 |

Not established, and what the mock does: proton.me sometimes signs under
`<26-character base32>.protonmail2` selectors that resolve to the same key;
the mock uses `protonmail2` only.

## Fastmail (fastmail.com)

The mock models a new plain-text message from the web client.

| Provider | Field | Observed value | Source | Checked |
|---|---|---|---|---|
| Fastmail | signatures | two `DKIM-Signature` fields: `d=fastmail.com` first, then `d=messagingengine.com` (not aligned), same selector and `t=`/`x=` | <https://lists.gnu.org/archive/mbox/help-gnu-emacs/2026-07> `<b69d9b0c-4ea5-46c1-85c0-1d349972bc50@app.fastmail.com>` | 2026-11-01 |
| Fastmail | tag order | `v a c d h s t x bh b` | same | 2026-11-01 |
| Fastmail | `t=` / `x=` | both; `x - t` = 86400 (1 day) | same | 2026-11-01 |
| Fastmail | selector | `fm2` (live); `fm1` and `fm3` published blanked on fastmail.com and messagingengine.com | live DNS | 2026-11-01 |
| Fastmail | `h=` | lower case, sorted; each of cc, content-type, date, from, in-reply-to, reply-to, subject, to listed once more than it occurs (oversigned even when absent); content-transfer-encoding, message-id, mime-version, references once if present. messagingengine.com adds feedback-id and x-me-sender (oversigned), x-me-proxy (once if present), x-sasl-enc (once) | same | 2026-11-01 |
| Fastmail | folding | Mail::DKIM: `prettify` over every tag but `b=` (margin 72, TAB to the next multiple of 8, `h=` broken before `:`, `bh=` anywhere), then `; b=` appended unbroken and the signature filled to the margin | `nntp://news.gmane.io/gmane.comp.version-control.git/563458` `<34b5c9c8-74d6-4d49-93cf-1d1909d56e9b@app.fastmail.com>`; Mail::DKIM 1.20240923 source | 2026-11-01 |
| Fastmail | header order (web) | Received x2 (internal) / DKIM-Signature (fastmail.com) / DKIM-Signature (messagingengine.com) / X-ME-Sender / X-ME-Proxy-Cause / X-ME-Proxy / Feedback-ID / Received / X-Mailer `MessagingEngine.com Webmail Interface` / MIME-Version / Date / From / To / Message-Id / Subject / Content-Type / Content-Transfer-Encoding | <https://lists.gnu.org/archive/mbox/help-gnu-emacs/2026-07> (above) | 2026-11-01 |
| Fastmail | shapes | From always quoted `"Name" <addr>`; Date `Tue, 28 Jul 2026 21:36:44 +0100` (padded, local offset); `Message-Id: <lower-case-uuid@app.fastmail.com>`; `text/plain` with `7bit` | same | 2026-11-01 |
| Fastmail | DNS | CNAME to `fmN.<domain>.dkim.fmhosted.com`; live `v=DKIM1; k=rsa; p=...`; rotated out `v=DKIM1; k=rsa; n=Intentionally_Left_Blank_As_Per_DKIM_Rotation_BCP; p=` | live DNS | 2026-11-01 |

Not established, and what the mock does: since October 2026 Fastmail also
adds experimental DKIM2 fields (`X-DKIM2-Info`, `DKIM2-Signature`,
`Message-Instance`, after draft-ietf-dkim-dkim2-spec) below its signatures;
the mock does not add them. The CNAME hop is not modeled. Fastmail's rotation
schedule was not established.

## GMX / WEB.DE (gmx.net, gmx.de, web.de)

The mock models a new message from the web client.

| Provider | Field | Observed value | Source | Checked |
|---|---|---|---|---|
| GMX | signatures | one | <https://lists.gnu.org/archive/mbox/emacs-devel/2026-06> `<87qzmqy0si.fsf@gmx.de>` | 2026-11-01 |
| GMX | tag order | `v a c d s t x i bh h b`; `i=` is the From address | same | 2026-11-01 |
| GMX | `t=` / `x=` | both; `x - t` = 604800 (7 days) | same | 2026-11-01 |
| GMX | selector | `s31663417` on every GMX domain; `s29768273` on web.de | same; live DNS | 2026-11-01 |
| GMX | `h=` | `X-UI-Sender-Class`, the signed headers present in message order with their case, then the oversigned tail `cc:content-transfer-encoding:content-type:date:from:message-id:mime-version:reply-to:subject:to` | same | 2026-11-01 |
| GMX | folding | line 1 `v a c d`; TAB-indented `s t x` line, `i=` joining it when the line stays within 68 columns; `bh`; `h=` broken after `:` within 68 columns (the closing `;` counts) and `b=` filled to 67, continued with TAB SP | `nntp://news.gmane.io/gmane.comp.version-control.git/562494` `<1MIdiZ-1xPjYn1zYD-005wYg@mail.gmx.net>` | 2026-11-01 |
| GMX | header order (web) | DKIM-Signature / X-UI-Sender-Class (a constant per brand) / Received (via HTTP) / MIME-Version / Message-ID / From / To / Subject / Content-Type / Date / X-UI-CLIENT-META-MAIL-DROP / X-Provags-ID / UI-OutboundReport / [Content-Transfer-Encoding when the body is re-encoded] | <https://lists.gnu.org/archive/mbox/emacs-devel/2026-06> (above); webmail position from `h=` | 2026-11-01 |
| GMX | Message-ID / Date | `<trinity-<uuid>-<13-digit ms>@trinity-msg-rest-gmx-gmx-live-<pod>>`; `Thu, 27 Aug 2026 23:22:42 +0000` (day not padded, `+0000`) | <https://lists.gnu.org/archive/mbox/bug-bash/2026-08> `<trinity-1929cbe7-74f0-4b56-875e-a095d08f27df-1787872961969@trinity-msg-rest-gmx-gmx-live-86cc48bb5b-v9796>` | 2026-11-01 |
| GMX | DNS | `v=DKIM1; p=...` (no `k=`); gmx.net and gmx.de publish the same key, web.de a different one | live DNS | 2026-11-01 |

Not established, and what the mock does: Mailman rewrote the web posts'
MIME-Version and Content-Type values; the mock uses `1.0` and
`text/plain; charset=UTF-8`. UI-OutboundReport is shorter than the observed
(about 5,800 characters) and random.

## Subject encoding

The circuit accepts the recovery statement only as the literal ASCII octets
of the relaxed-canonical Subject; an RFC 2047 encoded-word carrying the same
text is rejected (the `subject-encoded-word-*` fixtures). Of the 4,572
DKIM-signed posts from launch domains in the archives above (June to October
2026), one carries a pure-ASCII Subject as encoded-words: the iCloud web
client post in the iCloud table. What triggers that encoding (length, the
double space, or every web-client Subject) is not established from one
sample. No other launch provider's webmail or default client was seen
encoding a pure-ASCII Subject. A recovery email sent from the iCloud web
client may therefore be rejected and have to be resent from another client;
this is an open question for the recovery UX.

## What this means for parsing

Facts above that a circuit or input encoder has to handle, each exercised by
a fixture:

- Signature field names vary in case (`Dkim-Signature`), and providers add
  same-key copies under other names (`X-Google-DKIM-Signature`,
  `X-SONIC-DKIM-SIGN`), so a field-name match must be exact and
  case-insensitive, not a substring search.
- Fastmail always adds a second, non-aligned signature; only the one whose
  `d=` is the From domain may count.
- Outlook.com and iCloud list From and Subject once in `h=`, so a second,
  unsigned From or Subject placed above the signed one leaves DKIM valid
  (`unsigned-*-prepended-outlook`, `unsigned-*-prepended-icloud`). Gmail,
  Yahoo, Proton, Fastmail and GMX oversign both, so the same edit breaks
  their signature.
- Outlook.com writes no `t=`; Yahoo and Outlook.com write no `x=`.
- `bh=` comes before `h=` at iCloud, Yahoo, Proton and GMX, and after it at
  Gmail, Outlook.com and Fastmail; Fastmail breaks lines inside tag values.

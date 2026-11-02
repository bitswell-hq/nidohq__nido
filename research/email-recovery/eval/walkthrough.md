# Enrollment and recovery: an expert cognitive walkthrough

**This is an expert walkthrough by the people who designed the pages, not a
user study and not an independent review.** No participants took part. It
lists the problems an expert can predict from the current pages; it measures
neither completion rates nor error rates, and it cannot show how often real
users fall for a phishing script, tap the monthly check, or keep their
recovery code. Those need a study with participants, which is open. Its
ledger entry is `expert-walkthrough` in `research/email-recovery/claims.yaml`,
with status `unproven`.

## Method

A cognitive walkthrough: for each step of a task, the evaluator asks four
questions about a stated user.

1. Will the user try to do the right thing at this step?
2. Will the user notice that the right control is there?
3. Will the user connect that control with what they want?
4. After acting, will the user see that they made progress?

A "no" to any question is an issue. Each issue is rated by its consequence:
**severe** (the account can be lost or taken over), **major** (the task
fails or stalls), **minor** (friction or confusion that the user gets past).

The steps are those the wallet's pages render
(`packages/frontend/src/lib/recovery/emailEnrollPage.ts`, `emailBackup.ts`,
`recoverPage.ts`, `emailStep.ts`, `settingsPage.ts`, `liveAttempts.ts`), the
service worker's notifications (`packages/frontend/public/sw.js`), the alert
texts (`infra/email-alerts/src/vault/content.ts`), and those the local
end-to-end test drives in Chromium
(`tests/e2e/local/email-recovery.local.spec.ts`). The walkthrough was done by
reading that code and that test's script against the specification
(`docs/email-recovery/spec.md` §5, §9.3, §10, §11.4).

## Users and tasks

| User | Task |
| --- | --- |
| **Owner, enrolling.** Has the passkey on a laptop and a phone with the wallet installed; uses webmail; not technical. | Turn on email recovery (§5.4). |
| **Owner, recovering.** Lost every device; has a new phone, the recovery kit (printed or in a password manager), and can sign in to the inbox from the new phone. | Get back in with the email step and a second helper (§4, §6). |
| **Owner, phished.** Still has the passkey. A caller posing as Nido support has the owner read out the recovery code and send an email with a Subject the caller dictates, using the real recovery page on the caller's own device. | Notice and stop the attack. |
| **Owner, idle.** Recovery is set up and untouched for months; the owner may replace the phone in that time. | Keep it working: the code still at hand, alerts still arriving. |

## Enrollment

| Step | What the page asks | Finding |
| --- | --- | --- |
| 1. Recovery code | Save a 26-character code (Download, Print, Copy); optionally an encrypted copy in the enrollment email, with a five-word passphrase; then, with the code off the screen, type two of its groups back from where it was saved | Passes. The page says to keep the kit outside the inbox provider's account, naming Google Password Manager, Drive, iCloud Keychain and Files; on an iPhone, printing comes first and the page says a download goes to iCloud Drive. That is advice: nothing stops a Gmail user from saving the code in Google Password Manager (W5). |
| 2. Enrollment email | Send an email with an opaque Subject to the recovery address, from the inbox to enroll | Passes for a webmail user with a working `mailto:` handler; the page also shows To and Subject to copy. An opaque Subject is acceptable here: the owner is enrolling their own account with the passkey in hand. |
| 3. Alerts | An address for alerts (empty at first), notifications on this device, then the emailed confirmation code | Passes for most users. The enrolled inbox as alert address draws a warning, not a block (W6). When the inbox is at the platform that syncs the passkey (Google's or Apple's), read from the passkey's own backup flag and credential manager once it has signed on this device and from the browser otherwise, the page notes that the passkey and the inbox share that account and recommends another inbox or helper (W4). The consent text names the email services that deliver alerts and says this device will ask for a tap about once a month. On an iPhone or iPad outside the Home Screen app, the page says before asking for notifications to add this Nido's own address to the Home Screen. |
| 4. Email helper | Create the guardian contract | Passes; progress is shown and the page checks what was deployed. |
| 5. Recovery helpers | Choose how many helpers must approve | Passes; the page states the 7-day floor for email alone. |

## Recovery after losing every device

| Step | What the page asks | Finding |
| --- | --- | --- |
| 0. Find the page | The apex recovery page takes the Nido address from the kit, the recovery page's address, or the Nido's name | Passes. |
| 1. New passkey | Create a passkey on the new phone, open the attempt | Passes. |
| 2. Recovery code | Type the kit's code (or the block and its passphrase), under a warning that nobody from Nido asks for it and that the address bar must show exactly the kit's recovery page, on Nido's apex | Passes for an honest user: the address to compare comes from the build and the kit, not from the page's own host. |
| 3. The email | Send one email with an opaque Subject, picked up within 24 hours; the page shows when the window ends and offers a new email after it | Passes, with W7: a new phone may have no mail app for the `mailto:` link, and getting back into the inbox on a new device may need the lost one (provider prompts). |
| 4. Proving | Wait while the browser proves the email | Passes on desktop with the progress bar; phones are not measured (W8). |
| 5. Other helpers, the delay, completion | Share links; wait; finish | Passes. |

## The phished owner

| Step | What the user sees | Finding |
| --- | --- | --- |
| The caller dictates the Subject and asks for the code | The victim's own mail client and the caller's voice. The prepared email's warning line and the code-entry warning render on the caller's screen, not the victim's | Q1 fails, severe (W1): the only Nido text the victim has seen before acting is the kit's "Nobody from Nido will ask for this code", months earlier. |
| The vote is recorded; an alert arrives | Within one polling interval: an email and a push on every device set up for alerts, both saying "If someone told you to expect this message, or to ignore it, they are trying to take your account.", the push leading with "If you can still sign in to your Nido, you do not need a recovery: cancel it…" | Passes for a user who reads it. It arrives after the vote, so under a single required approval only the delay and the owner's cancellation are left; whether people act on it is not measured. |
| The owner opens the wallet on a passkey device | Every live attempt, those the email voted on first, with "Cancel this recovery" and, when many are open, a warning above them | Passes. |

## The idle owner

| Situation | Finding |
| --- | --- |
| Months later, is the code still the right one? | Passes: "Check my recovery code" compares a typed code with the guardian's pin, storing nothing, and the wallet opens it with a reminder about twice a year, never as a notification. |
| The owner replaced the phone and kept the old one, off or in a drawer, still subscribed | Passes in the end, with W2. The old phone stops confirming the monthly check; after two unconfirmed checks the device is unacknowledged and the alert address is told. Nothing on chain changes: the wallet says that the email helper still counts, and under email plus delay can still approve a recovery alone, offers "Add this device" and "Add another helper", and refuses settings in which email alone approves until a device confirms. On the new phone the settings page says where notifications go and offers "Add this device", which applies at once. Until then, and for 60 to 90 days after the old phone stopped, nothing tells the owner. |
| The monthly check itself | Q1 is at risk, minor to major (W3): the check is a Nido notification that asks for a tap every month, and tapping it may become a habit that carries over to real alerts. Real alerts look different (title "Security alert:", a red icon, they stay until dismissed); whether that is enough is not measured. |
| Someone opens recovery attempts every day | Passes: openings notify nobody, however many and for however long; the wallet lists every open attempt, approved ones first, with a warning when more than eight are open. |

## Open issues

| Id | Severity | Issue | Where |
| --- | --- | --- | --- |
| W1 | severe | A phished owner sees no Nido warning before sending the email: the page's warnings render on the attacker's screen; the alerts that pre-empt the script arrive after the vote | spec §11.4; a reply to each approval email from the recovery address is not built |
| W2 | major (severe under email plus delay with alerts to the enrolled inbox) | A device that stops confirming is found only at the third check after its last confirmation, 60 to 90 days later at the monthly default | spec §10.6 |
| W3 | minor to major | The monthly tap-to-confirm notification may train users to tap Nido notifications without reading them | spec §10.6, §13 question 20 |
| W4 | major | Where the passkey syncs through the inbox's own provider account, losing that account loses both; enrollment notes it but allows it, and the factor then adds little recovery | `syncedPasskeyNote`, spec §5.4 |
| W5 | severe if it happens | The kit can still be saved in the inbox provider's own password manager or drive; the page advises against it | `KIT_STORAGE_ADVICE` |
| W6 | severe if the push also fails | Alerts may go to the enrolled inbox, with a warning; a thief of that inbox deletes them | `alertAddressWarning` |
| W7 | major | No mail app for `mailto:` on a new phone; regaining the inbox may need the lost device | spec §13 |
| W8 | major | Phone proving is not measured | spec §12 |

The attack suite (`README.md` in this directory) runs the mechanisms behind
the passing steps on a local network: the phished owner cancelling from the
push, the residual risk for a phished owner with no device left, a lapsed
push, a switched phone, an email vote among 32 newer attempts, and repeated
attempts.

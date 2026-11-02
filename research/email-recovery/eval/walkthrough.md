# Enrollment and recovery: an expert cognitive walkthrough

**This is an expert heuristic walkthrough, not a user study.** No
participants took part. It finds problems an expert can predict from the
pages; it measures neither completion rates nor error rates, and it cannot
show how often real users fall for a phishing script or keep their recovery
code. Those need a study with participants, which is open.

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
`recoverPage.ts`, `emailStep.ts`, `settingsPage.ts`, `liveAttempts.ts`) and
those the local end-to-end test drives in Chromium
(`tests/e2e/local/email-recovery.local.spec.ts`). The walkthrough was done by
reading the pages' code and that test's script, against the specification
(`docs/email-recovery/spec.md` §5, §9.3, §10, §11.4).

## Users and tasks

| User | Task |
| --- | --- |
| **Owner, enrolling.** Has the passkey on a laptop and a phone with the wallet installed; uses webmail; not technical. | Turn on email recovery (§5.4). |
| **Owner, recovering.** Lost every device; has a new phone, the recovery kit (printed or in a password manager), and can sign in to the inbox from the new phone. | Get back in with the email step and a second helper (§4, §6). |
| **Owner, phished.** Still has the passkey. A caller posing as Nido support has the owner read out the recovery code and send an email with a Subject the caller dictates. | Notice and stop the attack. |
| **Owner, idle.** Recovery is set up and untouched for months. | Keep it working: the code still at hand, alerts still arriving. |

## Enrollment

| Step | What the page asks | Walkthrough finding |
| --- | --- | --- |
| 1. Recovery code | Save a 26-character code; optionally an encrypted copy in the enrollment email, with a five-word passphrase | Q4 failed: saving was a ticked box, so nothing showed the code was really saved (E1). Q1 failed for where to keep it: the obvious place for a Gmail or iCloud user is the same provider's password manager or drive, which an inbox thief then also holds (E2). The kit did not say which Nido it recovers (E3). |
| 2. Enrollment email | Send an email with an opaque Subject to the recovery address, from the inbox to enroll | Passes for a webmail user with a working `mailto:` handler; the page also shows To and Subject to copy. An opaque Subject is acceptable here: the owner is enrolling their own account with the passkey in hand. |
| 3. Alerts | An address for alerts, then notifications on this device, then the emailed confirmation code | Q1 failed: the address field was filled with the enrolled inbox, so most users would keep it, and an inbox thief can delete the alerts sent there (E4). On an iPhone, notifications need the wallet added to the Home Screen; the page says so only after the attempt fails (E5). |
| 4. Email helper | Create the guardian contract | Passes; progress is shown and the page checks what was deployed. |
| 5. Recovery helpers | Choose how many helpers must approve | Passes; the page states the 7-day floor for email alone. |

## Recovery after losing every device

| Step | What the page asks | Walkthrough finding |
| --- | --- | --- |
| 0. Find the page | The recovery page runs on the account's own subdomain, a 56-character address | Q2 failed: a user without any device has no way to know that address; the apex page only said to open "your Nido's address" (R1). |
| 1. New passkey | Create a passkey on the new phone, open the attempt | Passes. |
| 2. Recovery code | Type the kit's code (or the block and its passphrase) | Q3 failed for safety: the page gave no reason to check that it is the user's own Nido's page, and nothing said that nobody should ever ask for this code, which is exactly what a phishing script asks for (R2). |
| 3. The email | Send one email with an opaque Subject, picked up within 24 hours | Q4 failed after a day: the registration ends after 24 hours without telling the user, and the page then waits for an email it will never receive (R3). The prepared email's body said nothing to a user who was being talked into sending it (R4). A new phone may have no mail app for the `mailto:` link, and getting back into the inbox on a new device may need the lost one (provider prompts) (R5). |
| 4. Proving | Wait while the browser proves the email | Passes on desktop with the progress bar; phones are not measured (R6). |
| 5. Other helpers, the delay, completion | Share links; wait; finish | Passes. |

## The phished owner

| Step | What the user sees | Walkthrough finding |
| --- | --- | --- |
| The caller dictates the Subject and asks for the code | Nothing in the email or on any page contradicts the caller | Q1 failed: no copy tells the user that Nido never asks for an email or a code (R2, R4). |
| The attempt is approved; an alert arrives | The alert said that if the code matches the one the wallet shows, nothing needs doing; the caller sees the same code, since anyone with the recovery code computes it | Q1 failed, severe: the alert reassured exactly the user being attacked (A1). |
| The owner opens the wallet on a passkey device | Only the security settings page showed an approved attempt, with "I didn't ask for this: cancel it", and nothing for an attempt still collecting approvals | Q2 and Q3 failed: the home page showed nothing, and a phished user did ask, so the button's wording points away from cancelling (A2). |

## The idle owner

| Situation | Walkthrough finding |
| --- | --- |
| Months later, is the code still the right one? | Q2 failed: nothing let the user check a code before needing it (I1). |
| The phone's notifications for the wallet stopped (app removed, permission revoked, subscription expired) | Q4 failed, severe under email plus delay: nothing noticed or told the user, and the only remaining alert could go to the inbox a thief holds (I2). |
| Someone opens recovery attempts every day | Each opening sent an email saying it grants nothing, which teaches the user to ignore recovery alerts (I3). |

## Issues and what was done

| Id | Severity | Issue | Status | Where |
| --- | --- | --- | --- | --- |
| E1 | major | Saving the recovery code was a ticked box | **Fixed:** two groups of the code, picked at random, are typed back before enrollment continues | `emailBackup.ts`, `kitCheckMatches` |
| E2 | severe | The kit's natural home is the inbox provider's own password manager or drive | **Fixed:** the page and the kit advise keeping it outside the account behind the inbox, naming Google Password Manager, Drive, iCloud Keychain and Files | `KIT_STORAGE_ADVICE` |
| E3 | major | The kit did not name the Nido it recovers | **Fixed:** the kit names the Nido's address and its recovery page; the encrypted backup block carries the address inside its ciphertext | `recoveryKitText`, backup v2 (spec §5.6) |
| E4 | severe | Alerts defaulted to the enrolled inbox | **Fixed:** the field starts empty; the enrolled inbox draws a warning (not a block) with the reason | `alertAddressWarning` |
| E5 | minor | iPhone notifications need the Home Screen install, said only on failure | Open | `emailAlerts.ts` |
| R1 | severe | No way to find the account's recovery page after losing every device | **Fixed:** the apex recovery page takes the Nido address from the kit, the recovery page's address, or the Nido's name | `accountFromKitInput`, `recoverPage.ts` (spec §5.7) |
| R2 | severe | The code is typed with no warning and no origin check | **Fixed:** "Nobody from Nido will ask for this code", and the address bar to compare with the kit's address | `codeEntryWarning` |
| R3 | major | The 24-hour pickup window ended silently | **Fixed:** the page shows when it ends and offers a new email afterwards | `inboundDeadline`, `emailStep.ts` |
| R4 | severe | The prepared email said nothing to a user being talked into sending it | **Fixed:** its body opens with "If anyone asked you to send this email, stop. Nido never asks for this." | `NOBODY_ASKS_LINE` |
| R5 | major | No mail app for `mailto:` on a new phone; regaining the inbox may need the lost device | Open: To and Subject can be copied; the inbox's own recovery is the provider's | spec §13 |
| R6 | major | Phone proving is not measured | Open | spec §12 |
| A1 | severe | The alert reassured on a matching code, which a phisher also sees | **Fixed:** no alert reassures on a code; the push to the passkey device leads with "This device has your passkey, so you do not need a recovery. Cancel it unless you are deliberately replacing this passkey."; every email says what Nido never asks for | `content.ts` (spec §10.6) |
| A2 | severe | Only an approved attempt showed, on the settings page, with "I didn't ask for this" | **Fixed:** the wallet reads live attempts from the controller whenever it opens, collecting ones too, and offers "Cancel this recovery" with the passkey-device lead | `liveAttempts.ts` |
| I1 | major | No way to check the recovery code before needing it | **Fixed:** "Check my recovery code" compares the typed code with the guardian's pin, storing nothing | `checkCodeAgainstPin` (spec §5.6) |
| I2 | severe | A lapsed notification channel went unnoticed | **Fixed:** a weekly probe finds it, the alert address is told, the wallet shows it, refuses settings that keep the email helper (rule 2), and moves notifications to this device | spec §9.3, §10.3, §10.6 |
| I3 | minor | Daily "attempt opened" emails | **Fixed:** opening an attempt alerts nothing by default; the wallet shows open attempts | spec §10 |

The attack suite (`README.md` in this directory) runs the mechanisms behind
A1, A2, I2 and I3 on a local network: the phished owner cancelling from the
push, the residual risk for a phished owner with no device left, a lapsed
push, and ten repeated attempts.

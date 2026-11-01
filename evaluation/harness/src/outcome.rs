//! What happened to one attempted call, and which component refused it.

use nido_grant_signer::GrantError;
use serde::Serialize;
use stellar_accounts::smart_account::SmartAccountError;

/// One attempt's result. A refusal names the component that refused and its
/// error, as the component reported it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum Outcome {
    Allowed,
    Refused {
        component: String,
        error: String,
    },
    /// Not run on this backend, and why.
    NotRun {
        reason: String,
    },
}

impl Outcome {
    pub fn refused(component: &str, error: impl Into<String>) -> Self {
        Self::Refused {
            component: component.into(),
            error: error.into(),
        }
    }

    #[must_use]
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed)
    }
}

/// A grant signer error code as `Name (#code)`.
#[must_use]
pub fn grant_error(code: u32) -> String {
    match GrantError::try_from(soroban_sdk::Error::from_contract_error(code)) {
        Ok(e) => format!("{e:?} (#{code})"),
        Err(_) => format!("#{code}"),
    }
}

/// An `OpenZeppelin` smart-account error code as `Name (#code)`.
#[must_use]
pub fn account_error(code: u32) -> String {
    use SmartAccountError as E;
    let known = [
        E::ContextRuleNotFound,
        E::UnvalidatedContext,
        E::ExternalVerificationFailed,
        E::NoSignersAndPolicies,
        E::PastValidUntil,
        E::SignerNotFound,
        E::DuplicateSigner,
        E::PolicyNotFound,
        E::DuplicatePolicy,
        E::TooManySigners,
        E::TooManyPolicies,
        E::MathOverflow,
        E::KeyDataTooLarge,
        E::ContextRuleIdsLengthMismatch,
        E::NameTooLong,
        E::UnauthorizedSigner,
    ];
    known
        .iter()
        .find(|e| **e as u32 == code)
        .map_or_else(|| format!("#{code}"), |e| format!("{e:?} (#{code})"))
}

/// The first `Error(Type, Code)` in `text`, as written there.
#[must_use]
pub fn first_host_error(text: &str) -> Option<String> {
    let at = text.find("Error(")?;
    let rest = &text[at..];
    let end = rest.find(')')?;
    Some(rest[..=end].to_owned())
}

/// Host diagnostics that say why the host itself refused, and the reason the
/// results give for each.
const HOST_REASONS: [(&str, &str); 5] = [
    (
        "Unauthorized function call for address",
        "no authorization entry covers the call",
    ),
    (
        "nonce already exists for address",
        "the entry's nonce was already used",
    ),
    ("Contract re-entry is not allowed", "contract re-entry"),
    (
        "trustline entry is missing",
        "the recipient has no trustline",
    ),
    (
        "encountered authorization not tied to the root contract invocation",
        "recording simulation: authorization asked for below the root invocation",
    ),
];

/// The refusal a Soroban host error message records, given the grant
/// signer's and the account's strkeys, in this order: the grant signer's own
/// error event, a failed holder signature check in the grant signer, a host
/// refusal the diagnostics name, the account's authentication failure, and
/// otherwise the host's first error.
#[must_use]
pub fn classify(message: &str, signer: &str, account: &str) -> Outcome {
    let refusal = format!("contract:{signer}, topics:[error, Error(Contract, #");
    for line in message.lines() {
        if let Some(at) = line.find(&refusal) {
            let rest = &line[at + refusal.len()..];
            if let Some(code) = rest
                .find(')')
                .and_then(|end| rest[..end].parse::<u32>().ok())
            {
                return Outcome::refused("grant-signer", grant_error(code));
            }
        }
    }
    let signer_event = format!("contract:{signer}, topics:[error, ");
    for line in message.lines() {
        if line.contains(&signer_event) && line.contains("failed ED25519 verification") {
            let error = first_host_error(line).unwrap_or_default();
            return Outcome::refused(
                "grant-signer",
                format!("{error}: holder signature does not verify"),
            );
        }
    }
    for (phrase, reason) in HOST_REASONS {
        if message.contains(phrase) {
            let line = message
                .lines()
                .find(|l| l.contains(phrase))
                .unwrap_or_default();
            let error = first_host_error(line).unwrap_or_default();
            let component = if phrase.starts_with("trustline") {
                "token"
            } else {
                "host"
            };
            return Outcome::refused(component, format!("{error}: {reason}"));
        }
    }
    let auth = "\"failed account authentication with error\", ";
    for line in message.lines() {
        if let Some(at) = line.find(auth) {
            let rest = &line[at + auth.len()..];
            let (who, error) = rest.split_once(", ").unwrap_or((rest, ""));
            let error = error.trim_end_matches(']');
            let component = if who.contains(account) {
                "account"
            } else if who.contains(signer) {
                "grant-signer"
            } else {
                "host"
            };
            return Outcome::refused(component, contract_error(component, error));
        }
    }
    let error = first_host_error(message)
        .unwrap_or_else(|| message.lines().next().unwrap_or_default().to_owned());
    Outcome::refused("host", error)
}

/// `Error(Contract, #N)` named by `component`'s error enum.
fn contract_error(component: &str, error: &str) -> String {
    let code = error
        .strip_prefix("Error(Contract, #")
        .and_then(|r| r.strip_suffix(')'))
        .and_then(|n| n.parse::<u32>().ok());
    match (component, code) {
        ("account", Some(n)) => account_error(n),
        ("grant-signer", Some(n)) => grant_error(n),
        _ => error.to_owned(),
    }
}

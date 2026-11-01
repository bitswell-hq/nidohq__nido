//! Network wiring: the agent names a URL; the host checks it, resolves the
//! name, connects and follows redirects, checking each hop.
//!
//! The action for a URL is its host as the URL parser normalizes it
//! (lower-cased ASCII, IDNA names in their `xn--` form, IPv4 dotted, IPv6 in
//! brackets; a trailing dot is kept, so `example.com.` is a different host
//! from `example.com`), its port (the scheme's default when the URL gives
//! none) and its scheme. Only `http` and `https` URLs are fetched.
//!
//! The agent never gives an address for a name: the host's HTTP client does
//! the DNS lookup and the connecting, directly (no proxy), after the check.
//! Grants name hosts, not addresses, so what a name resolves to is trusted.
//!
//! The client follows no redirects itself. A `301`, `302`, `303`, `307` or
//! `308` with a `Location` is a new action: the target URL (resolved against
//! the current one) is checked like the first, and only then requested.

use std::time::Duration;

use url::{Host, Url};

/// An HTTP method the fetch tool offers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Method {
    Get,
    Post,
}

/// What the agent asks the host to fetch.
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub url: String,
    #[serde(default = "get")]
    pub method: Method,
    #[serde(default)]
    pub body: Option<String>,
}

fn get() -> Method {
    Method::Get
}

/// The network action a URL is checked as.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    pub host: String,
    pub port: u16,
    pub https: bool,
}

/// The [`Target`] for `url`.
///
/// # Errors
///
/// If `url` is not an `http` or `https` URL with a host.
pub fn target(url: &Url) -> Result<Target, NetError> {
    let https = match url.scheme() {
        "http" => false,
        "https" => true,
        other => return Err(NetError::Unsupported(format!("scheme {other:?}"))),
    };
    let host = match url.host() {
        Some(Host::Domain(name)) => name.to_owned(),
        Some(Host::Ipv4(addr)) => addr.to_string(),
        Some(Host::Ipv6(addr)) => format!("[{addr}]"),
        None => return Err(NetError::Unsupported("a URL with no host".into())),
    };
    let port = url
        .port_or_known_default()
        .ok_or_else(|| NetError::Unsupported("a URL with no port".into()))?;
    Ok(Target { host, port, https })
}

/// The response the agent gets back.
#[derive(Clone, Debug)]
pub struct Response {
    /// The URL that answered, after any redirects.
    pub url: String,
    pub status: u16,
    pub body: Vec<u8>,
}

/// Why a fetch did not complete.
#[derive(Debug)]
pub enum NetError {
    /// The grant denied this hop. `hop` is 0 for the requested URL and `n`
    /// for the `n`th redirect.
    Denied { url: String, hop: usize },
    /// Not something the fetch tool does.
    Unsupported(String),
    /// More redirects than the host follows.
    TooManyRedirects,
    /// The check could not run.
    Check(String),
    /// The request failed.
    Transport(String),
}

/// What [`fetch`] needs from the grant check.
pub trait Check {
    /// Whether the network grant allows connecting to `target`.
    ///
    /// # Errors
    ///
    /// If the check could not run; the fetch stops.
    fn allows(&mut self, target: &Target) -> Result<bool, String>;
}

/// The host's HTTP client settings.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_redirects: usize,
    pub max_body: u64,
    pub timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_redirects: 5,
            max_body: 16 << 20,
            timeout: Duration::from_secs(30),
        }
    }
}

/// An HTTP client that follows no redirects and uses no proxy.
#[must_use]
pub fn client(limits: &Limits) -> ureq::Agent {
    ureq::Agent::config_builder()
        .max_redirects(0)
        .proxy(None)
        .http_status_as_error(false)
        .timeout_global(Some(limits.timeout))
        .build()
        .new_agent()
}

/// Fetch `request` if `check` allows every hop.
///
/// # Errors
///
/// [`NetError::Denied`] for the first hop the grant denies; the other
/// variants for everything else.
pub fn fetch(
    http: &ureq::Agent,
    limits: &Limits,
    request: &Request,
    check: &mut impl Check,
) -> Result<Response, NetError> {
    let mut url = Url::parse(&request.url).map_err(|e| NetError::Unsupported(e.to_string()))?;
    let mut method = request.method;
    let mut body = request.body.clone();
    for hop in 0..=limits.max_redirects {
        let target = target(&url)?;
        if !check.allows(&target).map_err(NetError::Check)? {
            return Err(NetError::Denied {
                url: url.to_string(),
                hop,
            });
        }
        let result = match (method, &body) {
            (Method::Get, _) => http.get(url.as_str()).call(),
            (Method::Post, Some(b)) => http.post(url.as_str()).send(b.as_bytes()),
            (Method::Post, None) => http.post(url.as_str()).send_empty(),
        };
        let mut response = result.map_err(|e| NetError::Transport(e.to_string()))?;
        let status = response.status().as_u16();
        let location = response
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let (301 | 302 | 303 | 307 | 308, Some(redirect)) = (status, location) else {
            let body = response
                .body_mut()
                .with_config()
                .limit(limits.max_body)
                .read_to_vec()
                .map_err(|e| NetError::Transport(e.to_string()))?;
            return Ok(Response {
                url: url.to_string(),
                status,
                body,
            });
        };
        url = url
            .join(&redirect)
            .map_err(|e| NetError::Unsupported(format!("redirect to {redirect:?}: {e}")))?;
        // 303, and 301/302 after a POST, continue as a GET (RFC 9110 15.4);
        // 307 and 308 repeat the method and body.
        if status == 303 || (status != 307 && status != 308 && method == Method::Post) {
            method = Method::Get;
            body = None;
        }
    }
    Err(NetError::TooManyRedirects)
}

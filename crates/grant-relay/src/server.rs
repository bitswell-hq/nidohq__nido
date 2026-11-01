//! The HTTP front of a [`Relay`].
//!
//! | Route | |
//! | - | - |
//! | `POST /relay` | The agent's API key in the `x-api-key` header. |
//! | `POST /agents/{apiKey}/relay` | The API key in the path, for a client that only takes a base URL. |
//! | `OPTIONS` on either | CORS preflight, as the Caddy front of the Channels plugin answers it. |
//! | `GET /api/v1/health` | `200 {"status": "ok"}`. |
//!
//! Every `/relay` response carries `Access-Control-Allow-Origin: *`.

use std::io::Read;
use std::sync::Arc;
use std::thread::JoinHandle;

use nido_key_keeper::KeyKeeper;
use serde_json::{json, Value};
use tiny_http::{Header, Method, Response};

use crate::protocol::{self, MAX_BODY_BYTES};
use crate::rpc::SorobanRpc;
use crate::{Relay, RelayError};

/// A running relay server, serving until dropped.
pub struct Server {
    url: String,
    http: Arc<tiny_http::Server>,
    workers: Vec<JoinHandle<()>>,
}

impl Server {
    /// Bind `addr` (for example `127.0.0.1:0`) and serve `relay` with
    /// `workers` request threads.
    ///
    /// # Errors
    ///
    /// If `addr` cannot be bound.
    pub fn start<K, R>(relay: &Relay<K, R>, addr: &str, workers: usize) -> std::io::Result<Self>
    where
        K: KeyKeeper + Send + Sync + 'static,
        R: SorobanRpc + 'static,
    {
        let http = Arc::new(tiny_http::Server::http(addr).map_err(std::io::Error::other)?);
        let bound = http
            .server_addr()
            .to_ip()
            .ok_or_else(|| std::io::Error::other("not an IP listener"))?;
        let workers = (0..workers.max(1))
            .map(|_| {
                let http = Arc::clone(&http);
                let relay = relay.clone();
                std::thread::spawn(move || {
                    for request in http.incoming_requests() {
                        serve(&relay, request);
                    }
                })
            })
            .collect();
        Ok(Self {
            url: format!("http://{bound}"),
            http,
            workers,
        })
    }

    /// The server's base URL: the client's relay URL is this, or this plus
    /// `/agents/{apiKey}`.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Serve until the process ends.
    pub fn wait(mut self) {
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        for _ in &self.workers {
            self.http.unblock();
        }
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}

/// Where a request is going.
#[derive(Debug, PartialEq, Eq)]
enum Route<'a> {
    /// `/relay`, with the API key from the path when it was there.
    Relay {
        path_key: Option<&'a str>,
    },
    Health,
    NotFound,
}

fn route(path: &str) -> Route<'_> {
    match path {
        "/relay" => Route::Relay { path_key: None },
        "/api/v1/health" => Route::Health,
        _ => match path
            .strip_prefix("/agents/")
            .and_then(|rest| rest.strip_suffix("/relay"))
        {
            Some(key) if !key.is_empty() && !key.contains('/') => Route::Relay {
                path_key: Some(key),
            },
            _ => Route::NotFound,
        },
    }
}

fn serve<K, R>(relay: &Relay<K, R>, mut request: tiny_http::Request)
where
    K: KeyKeeper + Send + Sync + 'static,
    R: SorobanRpc + 'static,
{
    let url = request.url().to_owned();
    let path = url.split('?').next().unwrap_or("");
    let method = request.method().clone();
    let header_key = request
        .headers()
        .iter()
        .find(|h| h.field.equiv("x-api-key"))
        .map(|h| h.value.as_str().trim().to_owned());

    let response = match (route(path), method) {
        (Route::Relay { .. }, Method::Options) => Response::from_data(Vec::new())
            .with_status_code(204)
            .with_header(header("Access-Control-Allow-Methods", "POST, OPTIONS"))
            .with_header(header("Access-Control-Allow-Headers", "Content-Type"))
            .with_header(header("Access-Control-Max-Age", "86400")),
        (Route::Relay { path_key }, Method::Post) => {
            let mut body = Vec::new();
            let read = request
                .as_reader()
                .take(MAX_BODY_BYTES as u64 + 1)
                .read_to_end(&mut body);
            let result = if read.is_err() {
                Err(RelayError::invalid("Could not read the request body"))
            } else if body.len() > MAX_BODY_BYTES {
                Err(RelayError::new(
                    413,
                    "INVALID_PARAMS",
                    "Request body too large",
                ))
            } else {
                api_key(path_key, header_key.as_deref()).and_then(|key| {
                    protocol::parse_request(&body).and_then(|r| relay.handle(key, r))
                })
            };
            match result {
                Ok(data) => json_response(200, &protocol::success_body(&data)),
                Err(e) => json_response(e.status, &protocol::error_body(&e)),
            }
        }
        (Route::Health, Method::Get) => json_response(200, &json!({ "status": "ok" })),
        (Route::Relay { .. }, _) => json_response(
            405,
            &protocol::error_body(&RelayError::new(405, "METHOD_NOT_ALLOWED", "Use POST")),
        ),
        _ => json_response(
            404,
            &protocol::error_body(&RelayError::new(404, "NOT_FOUND", "No such route")),
        ),
    };
    let _ = request.respond(response.with_header(header("Access-Control-Allow-Origin", "*")));
}

/// The API key from the path or the header. When both are present they must
/// agree.
fn api_key<'a>(
    path_key: Option<&'a str>,
    header_key: Option<&'a str>,
) -> Result<Option<&'a str>, RelayError> {
    match (path_key, header_key) {
        (Some(p), Some(h)) if p != h => Err(RelayError::unauthorized(
            "The x-api-key header and the path name different API keys",
        )),
        (Some(k), _) | (None, Some(k)) => Ok(Some(k)),
        (None, None) => Ok(None),
    }
}

fn json_response(status: u16, body: &Value) -> Response<std::io::Cursor<Vec<u8>>> {
    Response::from_data(body.to_string().into_bytes())
        .with_status_code(status)
        .with_header(header("Content-Type", "application/json"))
}

fn header(name: &str, value: &str) -> Header {
    Header::from_bytes(name.as_bytes(), value.as_bytes()).expect("valid header")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes() {
        assert_eq!(route("/relay"), Route::Relay { path_key: None });
        assert_eq!(
            route("/agents/k1/relay"),
            Route::Relay {
                path_key: Some("k1")
            }
        );
        assert_eq!(route("/agents//relay"), Route::NotFound);
        assert_eq!(route("/agents/a/b/relay"), Route::NotFound);
        assert_eq!(route("/api/v1/health"), Route::Health);
        assert_eq!(route("/"), Route::NotFound);
    }

    #[test]
    fn path_and_header_keys_must_agree() {
        assert_eq!(api_key(Some("a"), None), Ok(Some("a")));
        assert_eq!(api_key(None, Some("b")), Ok(Some("b")));
        assert_eq!(api_key(Some("a"), Some("a")), Ok(Some("a")));
        assert_eq!(api_key(None, None), Ok(None));
        assert_eq!(api_key(Some("a"), Some("b")).unwrap_err().status, 401);
    }
}

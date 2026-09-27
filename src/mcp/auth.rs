//! Bearer token authorization for the MCP endpoint.
//!
//! The token is resolved once when the server starts, from the first source that is set:
//! 1. `WEB_TRANSPORT_MCP_TOKEN` environment variable (token value);
//! 2. `WEB_TRANSPORT_MCP_TOKEN_FILE` environment variable (path to a file, must exist);
//! 3. the default per-user file: `%LOCALAPPDATA%\WebTransport\mcp-token` on Windows,
//!    `$XDG_CONFIG_HOME/web-transport/mcp-token` (or `~/.config/...`) elsewhere.
//!
//! If none is set, authorization is disabled and the server behaves as before.

use std::convert::Infallible;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::http::{header, HeaderValue, Request, Response, StatusCode};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use tower::{Layer, Service};

use super::server::{BoxFutureResponse, BoxResponse};

pub(super) const TOKEN_ENV: &str = "WEB_TRANSPORT_MCP_TOKEN";
pub(super) const TOKEN_FILE_ENV: &str = "WEB_TRANSPORT_MCP_TOKEN_FILE";
const MIN_TOKEN_LEN: usize = 32;

#[derive(Clone)]
pub(super) struct BearerToken(Arc<str>);

impl BearerToken {
    pub(super) fn new(raw: &str) -> Result<Self, String> {
        let value = raw.trim_start_matches('\u{feff}').trim();
        if value.len() < MIN_TOKEN_LEN {
            return Err(format!("токен короче {MIN_TOKEN_LEN} символов"));
        }
        if !value.bytes().all(|b| b.is_ascii_graphic()) {
            return Err("токен содержит недопустимые символы".to_owned());
        }
        Ok(Self(Arc::from(value)))
    }

    fn matches(&self, authorization: Option<&HeaderValue>) -> bool {
        let Some(value) = authorization.and_then(|value| value.to_str().ok()) else {
            return false;
        };
        let Some((scheme, presented)) = value.split_once(' ') else {
            return false;
        };
        scheme.eq_ignore_ascii_case("bearer")
            && constant_time_eq(presented.trim().as_bytes(), self.0.as_bytes())
    }
}

impl fmt::Debug for BearerToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BearerToken(***)")
    }
}

/// Resolves the token from the process environment. The error never contains the token.
pub(super) fn resolve_token() -> Result<Option<BearerToken>, String> {
    resolve_token_from(
        std::env::var(TOKEN_ENV).ok(),
        std::env::var_os(TOKEN_FILE_ENV).map(PathBuf::from),
        default_token_path(),
    )
}

fn resolve_token_from(
    token: Option<String>,
    token_file: Option<PathBuf>,
    default_file: Option<PathBuf>,
) -> Result<Option<BearerToken>, String> {
    let describe = |source: &str, err: String| format!("Токен авторизации MCP ({source}): {err}");

    if let Some(token) = token.filter(|value| !value.trim().is_empty()) {
        return BearerToken::new(&token)
            .map(Some)
            .map_err(|err| describe(TOKEN_ENV, err));
    }

    if let Some(path) = token_file.filter(|path| !path.as_os_str().is_empty()) {
        return read_token_file(&path).map(Some);
    }

    match default_file {
        Some(path) if path.exists() => read_token_file(&path).map(Some),
        _ => Ok(None),
    }
}

fn read_token_file(path: &Path) -> Result<BearerToken, String> {
    let source = path.display().to_string();
    let raw = std::fs::read_to_string(path).map_err(|err| {
        format!("Токен авторизации MCP ({source}): не удалось прочитать файл: {err}")
    })?;
    BearerToken::new(&raw).map_err(|err| format!("Токен авторизации MCP ({source}): {err}"))
}

fn default_token_path() -> Option<PathBuf> {
    if cfg!(windows) {
        let base = std::env::var_os("LOCALAPPDATA")?;
        return Some(PathBuf::from(base).join("WebTransport").join("mcp-token"));
    }
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))?;
    Some(base.join("web-transport").join("mcp-token"))
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let diff = left
        .iter()
        .zip(right)
        .fold(0u8, |acc, (a, b)| acc | (a ^ b));
    std::hint::black_box(diff) == 0
}

#[derive(Clone)]
pub(super) struct BearerAuthLayer {
    pub(super) token: Option<BearerToken>,
}

impl<S> Layer<S> for BearerAuthLayer {
    type Service = BearerAuthService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        BearerAuthService {
            inner,
            token: self.token.clone(),
        }
    }
}

#[derive(Clone)]
pub(super) struct BearerAuthService<S> {
    inner: S,
    token: Option<BearerToken>,
}

impl<S, B> Service<Request<B>> for BearerAuthService<S>
where
    S: Service<Request<B>, Response = BoxResponse, Error = Infallible> + Clone + Send + 'static,
    S::Future: Send + 'static,
    B: Send + 'static,
{
    type Response = BoxResponse;
    type Error = Infallible;
    type Future = BoxFutureResponse;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        if let Some(token) = &self.token {
            if !token.matches(req.headers().get(header::AUTHORIZATION)) {
                return Box::pin(async { Ok(unauthorized_response()) });
            }
        }

        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        Box::pin(async move { inner.call(req).await })
    }
}

fn unauthorized_response() -> BoxResponse {
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(header::WWW_AUTHENTICATE, "Bearer")
        .body(Full::new(Bytes::from("Unauthorized")).boxed())
        .expect("valid response")
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "0123456789abcdef0123456789abcdef";

    fn header(value: &str) -> HeaderValue {
        HeaderValue::from_str(value).unwrap()
    }

    #[test]
    fn token_requires_min_length_and_visible_ascii() {
        assert!(BearerToken::new("short").is_err());
        assert!(BearerToken::new("0123456789abcdef 0123456789abcdef").is_err());
        assert!(BearerToken::new("0123456789abcdef0123456789abcdeё").is_err());
        assert!(BearerToken::new(TOKEN).is_ok());
    }

    #[test]
    fn token_is_trimmed_and_bom_is_ignored() {
        let token = BearerToken::new(&format!("\u{feff}{TOKEN}\r\n")).unwrap();
        assert!(token.matches(Some(&header(&format!("Bearer {TOKEN}")))));
    }

    #[test]
    fn matches_bearer_scheme_case_insensitively() {
        let token = BearerToken::new(TOKEN).unwrap();
        assert!(token.matches(Some(&header(&format!("bearer {TOKEN}")))));
        assert!(!token.matches(Some(&header(&format!("Basic {TOKEN}")))));
        assert!(!token.matches(Some(&header(TOKEN))));
        assert!(!token.matches(Some(&header("Bearer 0123456789abcdef0123456789abcdeX"))));
        assert!(!token.matches(None));
    }

    #[test]
    fn debug_does_not_reveal_token() {
        let token = BearerToken::new(TOKEN).unwrap();
        assert!(!format!("{token:?}").contains(TOKEN));
    }

    #[test]
    fn resolve_prefers_env_token_then_file_then_default() {
        let dir = std::env::temp_dir().join(format!("wt-auth-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("token");
        std::fs::write(&file, "fedcba9876543210fedcba9876543210").unwrap();
        let missing = dir.join("missing");

        let from_env = resolve_token_from(Some(TOKEN.into()), Some(file.clone()), None)
            .unwrap()
            .unwrap();
        assert!(from_env.matches(Some(&header(&format!("Bearer {TOKEN}")))));

        let from_file = resolve_token_from(Some("  ".into()), Some(file.clone()), None)
            .unwrap()
            .unwrap();
        assert!(from_file.matches(Some(&header("Bearer fedcba9876543210fedcba9876543210"))));

        let from_default = resolve_token_from(None, None, Some(file.clone())).unwrap();
        assert!(from_default.is_some());

        assert!(resolve_token_from(None, None, Some(missing.clone()))
            .unwrap()
            .is_none());
        assert!(resolve_token_from(None, None, None).unwrap().is_none());

        // An explicitly configured file must exist: fail closed instead of disabling auth.
        assert!(resolve_token_from(None, Some(missing), None).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_error_does_not_reveal_token() {
        let err = resolve_token_from(Some("secret-but-too-short".into()), None, None).unwrap_err();
        assert!(err.contains(TOKEN_ENV));
        assert!(!err.contains("secret-but-too-short"));
    }
}

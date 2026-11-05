//! `agentsafe serve`: the vault over HTTP on a Unix socket, behind `tailscale serve`.

mod ui;

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions, Permissions, TryLockError};
use std::future::poll_fn;
use std::io::ErrorKind;
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::pin::pin;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::rejection::BytesRejection;
use axum::extract::{DefaultBodyLimit, Extension, Path as UrlPath, Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde::{Deserialize, Serialize};
use tokio::net::UnixListener;
use tokio::signal::unix::{Signal, SignalKind, signal};
use tokio::sync::oneshot;

use crate::backend::{
    Backend, Caller, Exposed, LocalBackend, MetaPatch, Purpose, Put, Refusal, Selection, Values,
};
use crate::config::{Config, Mode, Serve};
use crate::policy::{self, Action, Rights};
use crate::vault::{Catalog, Store, validate_name};

const BODY_LIMIT: usize = 64 * 1024;
/// How long in-flight requests may run after SIGTERM or SIGINT.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub struct AppState {
    backend: Arc<LocalBackend>,
    /// `audit.jsonl`, which the admin UI reads.
    audit: Arc<Path>,
    /// Where the UI posts a notification when it reveals values.
    ntfy: Option<Arc<str>>,
}

/// The authenticated request, set by [`authorize`] for the handlers.
struct Ctx {
    caller: Caller,
    rights: Rights,
}

pub fn serve(config: Config, socket: Option<PathBuf>) -> Result<()> {
    let dir = config.dir().to_path_buf();
    let Mode::Local {
        identity,
        recipients,
    } = config.mode
    else {
        bail!(
            "serve needs a local config (`identity`), not a remote one: {}",
            config.path.display()
        );
    };
    let socket = socket_path(socket, &config.serve, &dir);
    let ntfy = config.serve.ntfy.as_deref().map(Arc::from);
    let backend = Arc::new(LocalBackend::new(
        Store::new(&dir, identity, recipients),
        &dir,
    ));
    // Held until the socket is removed: only its holder touches the socket path.
    let _lock = lock_socket(&socket)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        // Installed before the socket exists, so a signal sent once it appears is not lost.
        let term = signal(SignalKind::terminate())?;
        let int = signal(SignalKind::interrupt())?;
        let listener = bind(&socket)?;
        eprintln!("agentsafe: serving on {}", socket.display());
        let (stop, stopped) = oneshot::channel::<()>();
        let server = axum::serve(listener, app(backend, &dir, ntfy)).with_graceful_shutdown(async {
            let _ = stopped.await;
        });
        let mut server = pin!(server.into_future());
        let served = tokio::select! {
            served = &mut server => served,
            () = shutdown(term, int) => {
                let _ = stop.send(());
                // A stalled request is cut after the grace period. A write runs whole inside
                // `spawn_blocking` under `vault.lock`, so nothing committed is lost.
                match tokio::time::timeout(SHUTDOWN_GRACE, &mut server).await {
                    Ok(served) => served,
                    Err(_) => {
                        eprintln!("agentsafe: cut the requests still open after {SHUTDOWN_GRACE:?}");
                        Ok(())
                    }
                }
            }
        };
        let removed = fs::remove_file(&socket);
        served.context("server failed")?;
        removed.with_context(|| format!("cannot remove {}", socket.display()))
    })
}

fn socket_path(flag: Option<PathBuf>, serve: &Serve, dir: &Path) -> PathBuf {
    flag.or_else(|| serve.socket.as_ref().map(PathBuf::from))
        .or_else(|| {
            std::env::var_os("XDG_RUNTIME_DIR")
                .filter(|d| !d.is_empty())
                .map(|d| PathBuf::from(d).join("agentsafe.sock"))
        })
        .unwrap_or_else(|| dir.join("agentsafe.sock"))
}

/// An exclusive lock on `<socket>.lock`, refused while another server holds it.
fn lock_socket(socket: &Path) -> Result<File> {
    let mut path = socket.as_os_str().to_owned();
    path.push(".lock");
    let path = PathBuf::from(path);
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(&path)
        .with_context(|| format!("cannot open {}", path.display()))?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(TryLockError::WouldBlock) => bail!(
            "{} is in use by another agentsafe serve (it holds {})",
            socket.display(),
            path.display()
        ),
        Err(TryLockError::Error(e)) => {
            Err(e).with_context(|| format!("cannot lock {}", path.display()))
        }
    }
}

/// Binds inside a fresh 0700 directory, narrows the socket to 0600 and renames it into place,
/// so the socket is never reachable with wider permissions. The caller holds the socket lock, so
/// a socket already at the path is stale.
fn bind(path: &Path) -> Result<UnixListener> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => {
            fs::remove_file(path)
                .with_context(|| format!("cannot remove stale socket {}", path.display()))?;
        }
        Ok(_) => bail!("{} exists and is not a socket", path.display()),
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("cannot inspect {}", path.display())),
    }
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let tmp = tempfile::Builder::new()
        .prefix(".agentsafe-")
        .permissions(Permissions::from_mode(0o700))
        .tempdir_in(parent)
        .with_context(|| format!("cannot create a directory in {}", parent.display()))?;
    let staged = tmp.path().join("s");
    let listener =
        UnixListener::bind(&staged).with_context(|| format!("cannot bind {}", staged.display()))?;
    fs::set_permissions(&staged, Permissions::from_mode(0o600))?;
    fs::rename(&staged, path).with_context(|| format!("cannot create {}", path.display()))?;
    Ok(listener)
}

async fn shutdown(mut term: Signal, mut int: Signal) {
    poll_fn(|cx| {
        let term = term.poll_recv(cx).is_ready();
        let int = int.poll_recv(cx).is_ready();
        if term || int {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
    .await;
}

fn app(backend: Arc<LocalBackend>, dir: &Path, ntfy: Option<Arc<str>>) -> Router {
    let state = AppState {
        backend,
        audit: dir.join("audit.jsonl").into(),
        ntfy,
    };
    Router::new()
        .route("/api/v1/entries", get(list))
        .route(
            "/api/v1/entries/{name}",
            get(describe).put(put).delete(remove),
        )
        .route("/api/v1/fetch", post(fetch))
        .merge(ui::router(state.clone()))
        .layer(middleware::from_fn_with_state(state.clone(), authorize))
        .layer(DefaultBodyLimit::max(BODY_LIMIT))
        .with_state(state)
}

/// Runs on every request, matched or not: rights from the Serve headers, then the CSRF header.
async fn authorize(State(state): State<AppState>, mut req: Request, next: Next) -> Response {
    let headers = req.headers();
    let caller = caller(headers, req.uri().path());
    let (rights, warnings) = policy::parse(
        headers
            .get("tailscale-app-capabilities")
            .map(HeaderValue::as_bytes),
    );
    for w in warnings {
        eprintln!("agentsafe: warning: {w}");
    }
    let refused = match rights {
        Err(denial) => Some(denial.reason()),
        Ok(rights) => {
            let csrf = headers.get("sec-agentsafe").is_some_and(|v| v == "1");
            if req.uri().path().starts_with("/api/") && !csrf {
                Some("missing Sec-Agentsafe header")
            } else {
                req.extensions_mut().insert(Arc::new(Ctx {
                    caller: caller.clone(),
                    rights,
                }));
                None
            }
        }
    };
    let mut response = match refused {
        Some(reason) => {
            let (action, entry) = route_action(req.method(), req.uri().path());
            deny(&state, caller, action, entry, reason).await
        }
        None => next.run(req).await,
    };
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// `Tailscale-User-Login` for user nodes, else the source address of a tagged node. Requests
/// outside `/api/` come from the admin UI.
fn caller(headers: &HeaderMap, path: &str) -> Caller {
    let header = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .filter(|v| !v.is_empty())
    };
    let who = match (header("tailscale-user-login"), header("x-forwarded-for")) {
        (Some(login), _) => login.to_string(),
        (None, Some(addr)) => format!("node:{addr}"),
        (None, None) => "unknown".into(),
    };
    let via = if path.starts_with("/api/") {
        "api"
    } else {
        "ui"
    };
    Caller { who, via }
}

/// The audited action of a request refused before its handler ran.
fn route_action(method: &Method, path: &str) -> (&'static str, Option<String>) {
    let entry = path
        .strip_prefix("/api/v1/entries/")
        .filter(|n| !n.is_empty() && !n.contains('/'))
        .map(str::to_string);
    let action = match (method, path, &entry) {
        (&Method::GET, "/api/v1/entries", _) => "list",
        (&Method::POST, "/api/v1/fetch", _) => "get",
        (&Method::GET, _, Some(_)) => "describe",
        (&Method::PUT, _, Some(_)) => "put",
        (&Method::DELETE, _, Some(_)) => "rm",
        _ => "request",
    };
    (action, entry)
}

async fn deny(
    state: &AppState,
    caller: Caller,
    action: &'static str,
    entry: Option<String>,
    reason: &'static str,
) -> Response {
    let audited = blocking(state, move |b| {
        b.record_denied(&caller, action, entry.as_deref(), reason)
    })
    .await;
    if let Err(e) = audited {
        eprintln!("agentsafe: {e:#}");
    }
    ApiError(StatusCode::FORBIDDEN, reason.into()).into_response()
}

async fn blocking<T: Send + 'static>(
    state: &AppState,
    f: impl FnOnce(&LocalBackend) -> Result<T> + Send + 'static,
) -> Result<T> {
    let backend = state.backend.clone();
    tokio::task::spawn_blocking(move || f(&backend))
        .await
        .map_err(|e| anyhow!("vault task failed: {e}"))?
}

fn json(status: StatusCode, body: &impl Serialize) -> Response {
    let body = serde_json::to_vec(body).expect("API bodies always serialize");
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .expect("static response parts are valid")
}

/// An error answer, `{"error": message}`; never quotes a value or the request body.
struct ApiError(StatusCode, String);

type ApiResult = Result<Response, ApiError>;

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        json(self.0, &serde_json::json!({ "error": self.1 }))
    }
}

/// Vault errors never carry a value; caller mistakes keep their own status.
impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> ApiError {
        match e.downcast_ref::<Refusal>() {
            Some(r @ Refusal::NotFound(_)) => ApiError(StatusCode::NOT_FOUND, r.to_string()),
            Some(r @ Refusal::Invalid(_)) => ApiError(StatusCode::BAD_REQUEST, r.to_string()),
            None => {
                eprintln!("agentsafe: {e:#}");
                ApiError(StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}"))
            }
        }
    }
}

fn bad_request(message: impl Into<String>) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, message.into())
}

/// Parses a JSON body without ever echoing it: serde errors quote the input.
fn parse_body<T: for<'de> Deserialize<'de>>(
    body: Result<Bytes, BytesRejection>,
) -> Result<T, ApiError> {
    let body = body.map_err(|r| match r.status() {
        StatusCode::PAYLOAD_TOO_LARGE => ApiError(
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("request body over {BODY_LIMIT} bytes"),
        ),
        status => ApiError(status, "cannot read the request body".into()),
    })?;
    serde_json::from_slice(&body).map_err(|_| bad_request("invalid JSON body"))
}

fn checked_name(name: &str) -> Result<(), ApiError> {
    validate_name(name).map_err(|e| bad_request(e.to_string()))
}

#[derive(Serialize)]
struct Entries<T> {
    entries: T,
}

async fn list(State(state): State<AppState>, Extension(ctx): Extension<Arc<Ctx>>) -> ApiResult {
    let catalog = blocking(&state, |b| b.catalog()).await?;
    let entries: Catalog = catalog
        .into_iter()
        .filter(|(name, _)| ctx.rights.allows(Action::List, name))
        .collect();
    Ok(json(StatusCode::OK, &Entries { entries }))
}

async fn describe(
    State(state): State<AppState>,
    Extension(ctx): Extension<Arc<Ctx>>,
    UrlPath(name): UrlPath<String>,
) -> ApiResult {
    checked_name(&name)?;
    // Refused whether or not the entry exists, so the answer does not reveal it.
    if !ctx.rights.allows(Action::List, &name) {
        let caller = ctx.caller.clone();
        return Ok(deny(&state, caller, "describe", Some(name), "not allowed").await);
    }
    let mut catalog = blocking(&state, |b| b.catalog()).await?;
    match catalog.remove(&name) {
        Some(entry) => Ok(json(StatusCode::OK, &entry)),
        None => Err(anyhow::Error::from(Refusal::NotFound(name)).into()),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FetchBody {
    names: Option<Vec<String>>,
    all: Option<bool>,
}

async fn fetch(
    State(state): State<AppState>,
    Extension(ctx): Extension<Arc<Ctx>>,
    body: Result<Bytes, BytesRejection>,
) -> ApiResult {
    let body: FetchBody = parse_body(body)?;
    let names = match (body.names, body.all) {
        (Some(names), None) => {
            for name in &names {
                checked_name(name)?;
            }
            // One forbidden name refuses the whole request.
            if let Some(name) = names.iter().find(|n| !ctx.rights.allows(Action::Get, n)) {
                let (caller, name) = (ctx.caller.clone(), name.clone());
                return Ok(deny(&state, caller, "get", Some(name), "not allowed").await);
            }
            names
        }
        (None, Some(true)) => blocking(&state, |b| b.catalog())
            .await?
            .into_keys()
            .filter(|n| ctx.rights.allows(Action::Get, n))
            .collect(),
        _ => return Err(bad_request("give exactly one of `names` or `all: true`")),
    };
    let caller = ctx.caller.clone();
    let fetched = blocking(&state, move |b| {
        b.fetch_as(&caller, Purpose::Get, &Selection::Names(names))
    })
    .await?;
    let entries: BTreeMap<&str, Exposed> = fetched
        .iter()
        .map(|(name, values)| (name.as_str(), Exposed(values)))
        .collect();
    Ok(json(StatusCode::OK, &Entries { entries }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PutBody {
    values: Option<Values>,
    meta: Option<MetaPatch>,
}

async fn put(
    State(state): State<AppState>,
    Extension(ctx): Extension<Arc<Ctx>>,
    UrlPath(name): UrlPath<String>,
    body: Result<Bytes, BytesRejection>,
) -> ApiResult {
    checked_name(&name)?;
    let body: PutBody = parse_body(body)?;
    let meta = body.meta.unwrap_or_default();
    if body.values.is_none() && meta.is_empty() {
        return Err(bad_request("give `values`, `meta` or both"));
    }
    let action = if body.values.is_some() { "put" } else { "edit" };
    let caller = ctx.caller.clone();
    if !ctx.rights.allows(Action::Put, &name) {
        return Ok(deny(&state, caller, action, Some(name), "not allowed").await);
    }
    let put = Put {
        values: body.values,
        meta,
    };
    blocking(&state, move |b| b.put_as(&caller, &name, put)).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn remove(
    State(state): State<AppState>,
    Extension(ctx): Extension<Arc<Ctx>>,
    UrlPath(name): UrlPath<String>,
) -> ApiResult {
    checked_name(&name)?;
    let caller = ctx.caller.clone();
    if !ctx.rights.allows(Action::Admin, &name) {
        return Ok(deny(&state, caller, "rm", Some(name), "not allowed").await);
    }
    blocking(&state, move |b| b.remove_as(&caller, &name)).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

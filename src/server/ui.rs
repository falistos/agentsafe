//! The admin web UI: server-rendered pages for callers with `admin` on some entry, behind the
//! same authorization and audit as the API (`via: "ui"`).

use std::fs::File;
use std::io::{ErrorKind, Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use anyhow::Result;
use axum::Router;
use axum::extract::rejection::FormRejection;
use axum::extract::{Extension, Form, Path as UrlPath, Query, Request, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use jiff::civil::Date;
use minijinja::value::Serde;
use minijinja::{Environment, UndefinedBehavior, Value, context};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use super::{AppState, Ctx, blocking};
use crate::backend::{Backend, Expect, MetaPatch, Put, Refusal, Values};
use crate::dotenv;
use crate::policy::Action;
use crate::vault::{Catalog, CatalogEntry, Meta, validate_name};

const NTFY_TIMEOUT: Duration = Duration::from_secs(3);
const AUDIT_LINES: usize = 200;
/// How much of the end of `audit.jsonl` is read: far more than `AUDIT_LINES` lines.
const AUDIT_WINDOW: u64 = 512 * 1024;
const MIN_REASON_CHARS: usize = 4;
const MAX_REASON_CHARS: usize = 200;

static TEMPLATES: LazyLock<Environment<'static>> = LazyLock::new(|| {
    let mut env = Environment::new();
    env.set_undefined_behavior(UndefinedBehavior::Strict);
    let sources = [
        ("base.html", include_str!("templates/base.html")),
        ("error.html", include_str!("templates/error.html")),
        ("index.html", include_str!("templates/index.html")),
        (
            "meta_fields.html",
            include_str!("templates/meta_fields.html"),
        ),
        ("entry.html", include_str!("templates/entry.html")),
        ("new.html", include_str!("templates/new.html")),
        ("reveal.html", include_str!("templates/reveal.html")),
        ("audit.html", include_str!("templates/audit.html")),
    ];
    for (name, source) in sources {
        env.add_template(name, source)
            .expect("embedded templates parse");
    }
    env
});

pub fn router(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/", get(index))
        .route("/new", get(new_form).post(create))
        .route("/audit", get(audit))
        .route("/e/{name}", get(entry))
        .route("/e/{name}/meta", post(edit_meta))
        .route("/e/{name}/values", post(replace_values))
        .route("/e/{name}/reveal", post(reveal))
        .route("/e/{name}/delete", post(delete))
        .layer(middleware::from_fn_with_state(state, guard))
}

/// CSRF check on every request that is not a read. The security headers are set by `authorize`.
async fn guard(
    State(state): State<AppState>,
    Extension(ctx): Extension<Arc<Ctx>>,
    req: Request,
    next: Next,
) -> Response {
    let read = matches!(*req.method(), Method::GET | Method::HEAD);
    if read || same_origin(req.headers()) {
        next.run(req).await
    } else {
        record_denied(&state, &ctx, "request", None, "cross-origin request").await;
        UiError::new(StatusCode::FORBIDDEN, "Cross-origin request refused.").into_response()
    }
}

/// Go's `http.CrossOriginProtection`: `Sec-Fetch-Site` decides when the browser sends it, else
/// the `Origin` host must be the host the browser asked for, which Serve forwards.
fn same_origin(headers: &HeaderMap) -> bool {
    let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    match header("sec-fetch-site") {
        Some(site) => matches!(site, "same-origin" | "none"),
        None => match (
            header("origin").and_then(|o| o.split_once("://")),
            header("x-forwarded-host"),
        ) {
            (Some((_, host)), Some(forwarded)) => host.eq_ignore_ascii_case(forwarded.trim()),
            _ => false,
        },
    }
}

/// A refusal shown as a page; the message never holds a value.
struct UiError {
    status: StatusCode,
    message: String,
}

type UiResult = Result<Response, UiError>;

impl UiError {
    fn new(status: StatusCode, message: impl Into<String>) -> UiError {
        UiError {
            status,
            message: message.into(),
        }
    }

    fn bad_request(message: impl Into<String>) -> UiError {
        UiError::new(StatusCode::BAD_REQUEST, message)
    }
}

impl IntoResponse for UiError {
    fn into_response(self) -> Response {
        let page = context! {
            status => self.status.as_u16(),
            message => self.message,
            notice => Option::<&str>::None,
            audit => false,
        };
        render(self.status, "error.html", page)
    }
}

/// Vault errors never carry a value; the unexpected ones are logged, not shown.
impl From<anyhow::Error> for UiError {
    fn from(e: anyhow::Error) -> UiError {
        match e.downcast_ref::<Refusal>() {
            Some(r @ Refusal::NotFound(_)) => UiError::new(StatusCode::NOT_FOUND, r.to_string()),
            Some(r @ Refusal::Invalid(_)) => UiError::bad_request(r.to_string()),
            Some(r @ Refusal::Conflict(_)) => UiError::new(StatusCode::CONFLICT, r.to_string()),
            None => {
                eprintln!("agentsafe: {e:#}");
                UiError::new(StatusCode::INTERNAL_SERVER_ERROR, "Internal error.")
            }
        }
    }
}

fn render(status: StatusCode, template: &str, page: Value) -> Response {
    match TEMPLATES
        .get_template(template)
        .and_then(|t| t.render(page))
    {
        Ok(html) => (status, Html(html)).into_response(),
        Err(e) => {
            eprintln!("agentsafe: cannot render {template}: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal error.").into_response()
        }
    }
}

/// Admin on `*`: no entry name is matched by a pattern except the empty prefix.
fn admin_everywhere(ctx: &Ctx) -> bool {
    ctx.rights.allows(Action::Admin, "")
}

fn page(template: &str, ctx: &Ctx, extra: Value) -> Response {
    let page = context! { audit => admin_everywhere(ctx), ..extra };
    render(StatusCode::OK, template, page)
}

async fn record_denied(
    state: &AppState,
    ctx: &Ctx,
    action: &'static str,
    entry: Option<String>,
    reason: &'static str,
) {
    let caller = ctx.caller.clone();
    let audited = blocking(state, move |b| {
        b.record_denied(&caller, action, entry.as_deref(), reason)
    })
    .await;
    if let Err(e) = audited {
        eprintln!("agentsafe: {e:#}");
    }
}

async fn deny(state: &AppState, ctx: &Ctx, action: &'static str, entry: Option<String>) -> UiError {
    record_denied(state, ctx, action, entry, "not allowed").await;
    UiError::new(StatusCode::FORBIDDEN, "Not allowed.")
}

/// The entries the caller has `admin` on, or a 403 when no grant of theirs holds `admin`.
async fn admin_catalog(
    state: &AppState,
    ctx: &Ctx,
    action: &'static str,
) -> Result<Catalog, UiError> {
    if !ctx.rights.has_admin() {
        return Err(deny(state, ctx, action, None).await);
    }
    Ok(blocking(state, Backend::catalog)
        .await?
        .into_iter()
        .filter(|(name, _)| ctx.rights.allows(Action::Admin, name))
        .collect())
}

/// A valid name the caller has `admin` on, whether or not the entry exists.
async fn admin_name(
    state: &AppState,
    ctx: &Ctx,
    name: String,
    action: &'static str,
) -> Result<String, UiError> {
    validate_name(&name).map_err(|e| UiError::bad_request(e.to_string()))?;
    if ctx.rights.allows(Action::Admin, &name) {
        Ok(name)
    } else {
        Err(deny(state, ctx, action, Some(name)).await)
    }
}

/// The form fields, without echoing the body when it is refused.
fn form<T>(form: Result<Form<T>, FormRejection>) -> Result<T, UiError> {
    form.map(|Form(f)| f)
        .map_err(|r| UiError::new(r.status(), "Invalid form."))
}

#[derive(Deserialize)]
struct Done {
    done: Option<String>,
}

fn notice(done: Option<&str>) -> Option<&'static str> {
    match done {
        Some("created") => Some("Entry created."),
        Some("values") => Some("Values replaced."),
        Some("meta") => Some("Metadata saved."),
        Some("deleted") => Some("Entry deleted."),
        _ => None,
    }
}

#[derive(Serialize)]
struct EntryRow {
    name: String,
    description: String,
    owner: String,
    used_by: Vec<String>,
    tags: Vec<String>,
    rotate_by: String,
    overdue: bool,
    keys: Vec<String>,
    unmasked: Vec<String>,
}

impl EntryRow {
    fn new(name: String, entry: CatalogEntry, today: Date) -> EntryRow {
        let meta = entry.meta;
        EntryRow {
            name,
            description: meta.description.unwrap_or_default(),
            owner: meta.owner.unwrap_or_default(),
            used_by: meta.used_by,
            tags: meta.tags,
            rotate_by: meta.rotate_by.map(|d| d.to_string()).unwrap_or_default(),
            overdue: meta.rotate_by.is_some_and(|d| d < today),
            keys: entry.keys,
            unmasked: entry.unmasked,
        }
    }
}

async fn index(
    State(state): State<AppState>,
    Extension(ctx): Extension<Arc<Ctx>>,
    Query(done): Query<Done>,
) -> UiResult {
    let today = jiff::Zoned::now().date();
    let entries: Vec<EntryRow> = admin_catalog(&state, &ctx, "list")
        .await?
        .into_iter()
        .map(|(name, entry)| EntryRow::new(name, entry, today))
        .collect();
    let extra = context! { entries => Value::from(Serde(&entries)), notice => notice(done.done.as_deref()) };
    Ok(page("index.html", &ctx, extra))
}

async fn entry(
    State(state): State<AppState>,
    Extension(ctx): Extension<Arc<Ctx>>,
    UrlPath(name): UrlPath<String>,
    Query(done): Query<Done>,
) -> UiResult {
    let name = admin_name(&state, &ctx, name, "describe").await?;
    let mut catalog = blocking(&state, Backend::catalog).await?;
    let Some(found) = catalog.remove(&name) else {
        return Err(anyhow::Error::from(Refusal::NotFound(name)).into());
    };
    let e = EntryRow::new(name, found, jiff::Zoned::now().date());
    let extra = context! {
        e => Value::from(Serde(&e)),
        ntfy => state.ntfy.is_some(),
        notice => notice(done.done.as_deref()),
    };
    Ok(page("entry.html", &ctx, extra))
}

#[derive(Deserialize)]
struct MetaForm {
    #[serde(default)]
    description: String,
    #[serde(default)]
    used_by: String,
    #[serde(default)]
    owner: String,
    #[serde(default)]
    rotate_by: String,
    #[serde(default)]
    tags: String,
}

impl MetaForm {
    /// Every field is sent, so an empty one clears it. List items are one per line, so an item
    /// may contain a comma.
    fn patch(self) -> MetaPatch {
        let list = |s: &str| -> Vec<String> {
            s.lines()
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(str::to_string)
                .collect()
        };
        MetaPatch {
            description: Some(self.description.trim().into()),
            used_by: Some(list(&self.used_by)),
            owner: Some(self.owner.trim().into()),
            rotate_by: Some(self.rotate_by.trim().into()),
            tags: Some(list(&self.tags)),
            source: None,
        }
    }
}

/// `KEY=VALUE` lines as `set` reads them. The error names a line, never its content.
fn parse_values(text: &str) -> Result<Values, UiError> {
    let parsed =
        dotenv::parse(text).map_err(|e| UiError::bad_request(format!("Invalid values: {e}.")))?;
    Ok(parsed
        .into_iter()
        .map(|(k, v)| (k, SecretString::from(v)))
        .collect())
}

fn redirect(name: &str, done: &str) -> Response {
    Redirect::to(&format!("/e/{name}?done={done}")).into_response()
}

async fn edit_meta(
    State(state): State<AppState>,
    Extension(ctx): Extension<Arc<Ctx>>,
    UrlPath(name): UrlPath<String>,
    body: Result<Form<MetaForm>, FormRejection>,
) -> UiResult {
    let name = admin_name(&state, &ctx, name, "edit").await?;
    let put = Put {
        values: None,
        meta: form(body)?.patch(),
    };
    let (caller, target) = (ctx.caller.clone(), name.clone());
    blocking(&state, move |b| b.put_as(&caller, &target, put)).await?;
    Ok(redirect(&name, "meta"))
}

#[derive(Deserialize)]
struct ValuesForm {
    values: String,
}

async fn replace_values(
    State(state): State<AppState>,
    Extension(ctx): Extension<Arc<Ctx>>,
    UrlPath(name): UrlPath<String>,
    body: Result<Form<ValuesForm>, FormRejection>,
) -> UiResult {
    let name = admin_name(&state, &ctx, name, "put").await?;
    let put = Put {
        values: Some(parse_values(&form(body)?.values)?),
        meta: MetaPatch::default(),
    };
    let (caller, target) = (ctx.caller.clone(), name.clone());
    // A typo in the URL must not create an entry: that is what the new-entry page is for.
    blocking(&state, move |b| {
        b.put_expecting(&caller, &target, put, Expect::Exists)
    })
    .await?;
    Ok(redirect(&name, "values"))
}

async fn new_form(State(state): State<AppState>, Extension(ctx): Extension<Arc<Ctx>>) -> UiResult {
    admin_catalog(&state, &ctx, "put").await?;
    let blank = EntryRow::new(
        String::new(),
        CatalogEntry {
            meta: Meta::default(),
            keys: Vec::new(),
            unmasked: Vec::new(),
        },
        jiff::Zoned::now().date(),
    );
    let extra = context! { e => Value::from(Serde(&blank)), notice => Option::<&str>::None };
    Ok(page("new.html", &ctx, extra))
}

#[derive(Deserialize)]
struct NewForm {
    name: String,
    values: String,
    #[serde(flatten)]
    meta: MetaForm,
}

async fn create(
    State(state): State<AppState>,
    Extension(ctx): Extension<Arc<Ctx>>,
    body: Result<Form<NewForm>, FormRejection>,
) -> UiResult {
    let new = form(body)?;
    let name = admin_name(&state, &ctx, new.name.trim().to_string(), "put").await?;
    let put = Put {
        values: Some(parse_values(&new.values)?),
        meta: new.meta.patch(),
    };
    let (caller, target) = (ctx.caller.clone(), name.clone());
    blocking(&state, move |b| {
        b.put_expecting(&caller, &target, put, Expect::Absent)
    })
    .await?;
    Ok(redirect(&name, "created"))
}

#[derive(Deserialize)]
struct RevealForm {
    reason: String,
}

#[derive(Serialize)]
struct Revealed {
    key: String,
    value: String,
}

async fn reveal(
    State(state): State<AppState>,
    Extension(ctx): Extension<Arc<Ctx>>,
    UrlPath(name): UrlPath<String>,
    body: Result<Form<RevealForm>, FormRejection>,
) -> UiResult {
    let name = admin_name(&state, &ctx, name, "reveal").await?;
    let reason = form(body)?.reason;
    let reason = reason.trim();
    if reason.chars().filter(|c| !c.is_whitespace()).count() < MIN_REASON_CHARS {
        return Err(UiError::bad_request(format!(
            "Give a reason of at least {MIN_REASON_CHARS} characters."
        )));
    }
    let reason: String = reason.chars().take(MAX_REASON_CHARS).collect();
    let (caller, target, ntfy) = (ctx.caller.clone(), name.clone(), state.ntfy.clone());
    let values = blocking(&state, move |b| {
        let notify = ntfy
            .as_deref()
            .map(|url| move |message: &str| post_ntfy(url, message));
        b.reveal_as(&caller, &target, &reason, notify)
    })
    .await?;
    let values: Vec<Revealed> = values
        .iter()
        .map(|(key, value)| Revealed {
            key: key.clone(),
            value: value.expose_secret().to_string(),
        })
        .collect();
    // `authorize` sets `Cache-Control: no-store` on this answer like on every other.
    let extra = context! { name => name, values => Value::from(Serde(&values)), notice => Option::<&str>::None };
    Ok(page("reveal.html", &ctx, extra))
}

/// Posts the message to the ntfy topic; whether it was delivered. The error is not logged: it
/// can quote the URL, whose topic is a secret.
fn post_ntfy(url: &str, message: &str) -> bool {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(NTFY_TIMEOUT))
        .build()
        .into();
    let sent = agent
        .post(url)
        .header("Title", "agentsafe reveal")
        .content_type("text/plain; charset=utf-8")
        .send(message)
        .is_ok();
    if !sent {
        eprintln!("agentsafe: the ntfy notification failed");
    }
    sent
}

#[derive(Deserialize)]
struct DeleteForm {
    confirm: String,
}

async fn delete(
    State(state): State<AppState>,
    Extension(ctx): Extension<Arc<Ctx>>,
    UrlPath(name): UrlPath<String>,
    body: Result<Form<DeleteForm>, FormRejection>,
) -> UiResult {
    let name = admin_name(&state, &ctx, name, "rm").await?;
    if form(body)?.confirm.trim() != name {
        return Err(UiError::bad_request(
            "The confirmation does not match the entry name.",
        ));
    }
    let caller = ctx.caller.clone();
    blocking(&state, move |b| b.remove_as(&caller, &name)).await?;
    Ok(Redirect::to("/?done=deleted").into_response())
}

#[derive(Serialize, Deserialize, Default)]
#[serde(default)]
struct AuditRow {
    ts: String,
    who: String,
    via: String,
    action: String,
    entry: String,
    result: String,
    reason: String,
    notify: String,
}

async fn audit(State(state): State<AppState>, Extension(ctx): Extension<Arc<Ctx>>) -> UiResult {
    if !admin_everywhere(&ctx) {
        return Err(deny(&state, &ctx, "audit", None).await);
    }
    let path = Arc::clone(&state.audit);
    let rows = blocking(&state, move |_| audit_tail(&path)).await?;
    let extra = context! { rows => Value::from(Serde(&rows)), notice => Option::<&str>::None };
    Ok(page("audit.html", &ctx, extra))
}

/// The last `AUDIT_LINES` events, newest first. Lines that do not parse are skipped.
fn audit_tail(path: &Path) -> Result<Vec<AuditRow>> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    let start = file.metadata()?.len().saturating_sub(AUDIT_WINDOW);
    file.seek(SeekFrom::Start(start))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let text = String::from_utf8_lossy(&bytes);
    let mut lines = text.lines();
    if start > 0 {
        // The window begins inside a line.
        lines.next();
    }
    let rows: Vec<AuditRow> = lines.filter_map(|l| serde_json::from_str(l).ok()).collect();
    Ok(rows.into_iter().rev().take(AUDIT_LINES).collect())
}

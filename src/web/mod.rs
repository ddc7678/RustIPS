//! Embedded web UI: a small synchronous HTTP/1.1 server on `std::net` plus the
//! authenticated admin routes (FR-180…FR-190).
//!
//! Design rules:
//!
//! * Bound to loopback by default. A non-loopback bind is explicit, logged,
//!   and shown as a persistent banner.
//! * PAM is the only password store. Sessions live in memory, carry a CSRF
//!   token, and are revalidated against PAM and the admin group.
//! * No templating crate and no asset directory: the pages are `format!`
//!   strings and the CSS/JS are compiled into the binary.
//! * Every stored or request-derived value is HTML-escaped, and the response
//!   carries a strict Content-Security-Policy.

pub mod pages;
pub mod session;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use chrono::Utc;

use crate::auth::{self, AuthOutcome, LoginLimiter};
use crate::config::{BlockDuration, Config, Mode, UnblockEffect};
use crate::countries;
use crate::daemon::Stats;
use crate::db::Db;
use crate::enforce::Enforcer;
use crate::error::{Error, Result};
use crate::firewall;
use crate::geo::GeoHandle;
use crate::model::{Actor as ModelActor, BlockState};
use crate::net::{self, Cidr};
use crate::paths::Layout;
use crate::rules::{History, RuleForm, RuleSet};
use crate::web::session::{SessionView, Sessions};

const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_BODY_BYTES: usize = 8 * 1024;
/// Rule import posts a whole JSON document; still bounded.
const MAX_IMPORT_BYTES: usize = 256 * 1024;
const MAX_CONNECTIONS: usize = 64;
const READ_TIMEOUT: Duration = Duration::from_secs(5);
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
const PAGE_SIZE: u32 = 50;
const COOKIE: &str = "rustips_session";

const CSS: &str = include_str!("assets/app.css");
const JS: &str = include_str!("assets/app.js");
const THEME_JS: &str = include_str!("assets/theme.js");

const CSP: &str = "default-src 'none'; style-src 'self'; script-src 'self'; \
                   img-src 'self' data:; connect-src 'self'; form-action 'self'; \
                   frame-ancestors 'none'; base-uri 'none'";

// ------------------------------------------------------------------- options

/// CLI overrides. `None` means "fall through to environment, database, file".
#[derive(Debug, Clone, Default)]
pub struct WebOptions {
    pub bind: Option<String>,
    pub port: Option<u16>,
}

pub struct WebHandle {
    pub addr: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl WebHandle {
    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for WebHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

struct Ctx {
    cfg: Config,
    /// Configuration before DB parameter overrides, used to validate changes.
    baseline: Config,
    db_path: PathBuf,
    state_dir: PathBuf,
    stats: Arc<Stats>,
    enforcer: Arc<dyn Enforcer>,
    geo: GeoHandle,
    sessions: Sessions,
    limiter: LoginLimiter,
    started: Instant,
    bind: SocketAddr,
    version: String,
    /// Serialises settings writes with a test-bind.
    settings_lock: Mutex<()>,
}

// --------------------------------------------------------------------- start

/// Bind and start the UI. Failure to bind is returned to the caller so the
/// daemon can log it and keep protecting the host without a UI.
pub fn start(
    cfg: &Config,
    layout: &Layout,
    stats: Arc<Stats>,
    enforcer: Arc<dyn Enforcer>,
    geo: GeoHandle,
    opts: WebOptions,
) -> Result<WebHandle> {
    let (wanted, from_db) = resolve_bind(cfg, layout, &opts)?;
    let listener = match TcpListener::bind(wanted) {
        Ok(listener) => listener,
        Err(e) if from_db => {
            tracing::warn!(
                addr = %wanted,
                error = %e,
                "cannot bind the saved web override; reverting to the configuration file"
            );
            if let Ok(db) = Db::open(&layout.db) {
                let _ = db.delete_setting("web.bind");
                let _ = db.delete_setting("web.port");
                let _ = db.audit(
                    &ModelActor::System,
                    "settings.web.reverted",
                    &wanted.to_string(),
                    &format!("bind failed: {e}"),
                );
            }
            let fallback = SocketAddr::new(
                cfg.web
                    .bind
                    .parse()
                    .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                cfg.web.port,
            );
            TcpListener::bind(fallback).map_err(|e2| {
                Error::Other(format!(
                    "cannot bind web UI to {wanted} ({e}) or {fallback} ({e2})"
                ))
            })?
        }
        Err(e) => {
            return Err(Error::Other(format!("cannot bind web UI to {wanted}: {e}")));
        }
    };
    listener.set_nonblocking(true)?;
    let local = listener.local_addr()?;

    if local.ip().is_loopback() {
        tracing::info!(addr = %local, "web UI listening (loopback)");
    } else {
        tracing::warn!(
            addr = %local,
            "web UI listening on a non-loopback address; use an SSH tunnel or TLS in front of it"
        );
    }

    if let Ok(db) = Db::open(&layout.db) {
        let _ = db.bootstrap_alert_target(cfg);
    }

    let baseline = Config::load(&layout.config).unwrap_or_else(|e| {
        tracing::debug!(error = %e, "using built-in defaults as the parameter baseline");
        Config::defaults()
    });

    let ctx = Arc::new(Ctx {
        cfg: cfg.clone(),
        baseline,
        db_path: layout.db.clone(),
        state_dir: layout.state_dir.clone(),
        stats,
        enforcer,
        geo,
        sessions: Sessions::new(
            Duration::from_secs(cfg.web.session_idle_mins.saturating_mul(60)),
            Duration::from_secs(cfg.web.session_absolute_mins.saturating_mul(60)),
            Duration::from_secs(cfg.web.revalidate_mins.saturating_mul(60)),
        ),
        limiter: LoginLimiter::new(),
        started: Instant::now(),
        bind: local,
        version: crate::VERSION.to_string(),
        settings_lock: Mutex::new(()),
    });

    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = stop.clone();
    let thread = std::thread::Builder::new()
        .name("rustips-web".into())
        .spawn(move || accept_loop(listener, ctx, stop_thread))
        .map_err(|e| Error::Other(format!("cannot start web thread: {e}")))?;

    Ok(WebHandle {
        addr: local,
        stop,
        thread: Some(thread),
    })
}

/// Precedence: CLI > environment > database override > configuration file.
/// Returns the address to try and whether it came from the database (the only
/// source that may be reverted silently).
fn resolve_bind(cfg: &Config, layout: &Layout, opts: &WebOptions) -> Result<(SocketAddr, bool)> {
    let mut bind = None;
    let mut port = None;
    let mut from_db = false;

    if let Some(value) = opts.bind.clone() {
        bind = Some(parse_ip(&value)?);
    }
    if let Some(value) = opts.port {
        if value == 0 {
            return Err(Error::Config("--web-port must be 1..=65535".into()));
        }
        port = Some(value);
    }
    if bind.is_none()
        && let Ok(value) = std::env::var("RUSTIPS_WEB_BIND")
    {
        bind = Some(parse_ip(&value)?);
    }
    if port.is_none()
        && let Ok(value) = std::env::var("RUSTIPS_WEB_PORT")
    {
        let value: u16 = value
            .parse()
            .map_err(|_| Error::Config(format!("RUSTIPS_WEB_PORT {value:?} is not a port")))?;
        if value == 0 {
            return Err(Error::Config("RUSTIPS_WEB_PORT must be 1..=65535".into()));
        }
        port = Some(value);
    }
    if (bind.is_none() || port.is_none())
        && let Ok(db) = Db::open(&layout.db)
    {
        if bind.is_none()
            && let Ok(Some(value)) = db.get_setting("web.bind")
            && let Some(text) = value.as_str()
            && let Ok(addr) = parse_ip(text)
        {
            bind = Some(addr);
            from_db = true;
        }
        if port.is_none()
            && let Ok(Some(value)) = db.get_setting("web.port")
            && let Some(number) = value.as_u64()
        {
            port = Some(number as u16);
            from_db = true;
        }
    }

    let addr = bind.unwrap_or_else(|| {
        cfg.web
            .bind
            .parse()
            .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST))
    });
    let port = port.unwrap_or(cfg.web.port);
    if port == 0 {
        return Err(Error::Config("web port must be 1..=65535".into()));
    }
    Ok((SocketAddr::new(addr, port), from_db))
}

fn parse_ip(value: &str) -> Result<IpAddr> {
    value
        .trim()
        .parse::<IpAddr>()
        .map(net::normalise)
        .map_err(|_| Error::Config(format!("{value:?} is not an IP address")))
}

fn accept_loop(listener: TcpListener, ctx: Arc<Ctx>, stop: Arc<AtomicBool>) {
    let active = Arc::new(AtomicUsize::new(0));
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((mut stream, _peer)) => {
                if active.fetch_add(1, Ordering::Relaxed) >= MAX_CONNECTIONS {
                    active.fetch_sub(1, Ordering::Relaxed);
                    let _ =
                        write_response(&mut stream, &Response::text(503, "text/plain", "busy\n"));
                    continue;
                }
                let ctx = ctx.clone();
                let active = Arc::clone(&active);
                std::thread::spawn(move || {
                    let _guard = ConnGuard(active);
                    handle_connection(stream, ctx);
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(e) => {
                tracing::warn!("web accept failed: {e}");
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    }
}

struct ConnGuard(Arc<AtomicUsize>);

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

fn handle_connection(mut stream: TcpStream, ctx: Arc<Ctx>) {
    let peer = stream
        .peer_addr()
        .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
    let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
    let _ = stream.set_write_timeout(Some(WRITE_TIMEOUT));
    let _ = stream.set_nodelay(true);

    let request = match read_request(&mut stream, peer) {
        Ok(request) => request,
        Err(e) => {
            let _ = write_response(&mut stream, &e.response());
            return;
        }
    };

    if !host_allowed(&request, ctx.bind) {
        let _ = write_response(
            &mut stream,
            &Response::text(421, "text/plain", "misdirected request\n"),
        );
        return;
    }

    let response = route(&ctx, &request);
    let _ = write_response(&mut stream, &response);
}

// ------------------------------------------------------------------- request

struct Request {
    method: String,
    path: String,
    http11: bool,
    headers: HashMap<String, String>,
    query: HashMap<String, String>,
    form: HashMap<String, String>,
    peer: SocketAddr,
}

impl Request {
    fn param(&self, name: &str) -> Option<&str> {
        self.form
            .get(name)
            .or_else(|| self.query.get(name))
            .map(String::as_str)
    }

    fn cookie(&self, name: &str) -> Option<String> {
        let raw = self.headers.get("cookie")?;
        for part in raw.split(';') {
            let part = part.trim();
            if let Some((key, value)) = part.split_once('=')
                && key == name
            {
                return Some(value.to_string());
            }
        }
        None
    }
}

enum RequestError {
    BadRequest(&'static str),
    TooLarge,
    Unsupported(&'static str),
}

impl RequestError {
    fn response(&self) -> Response {
        match self {
            RequestError::BadRequest(text) => {
                Response::text(400, "text/plain", &format!("bad request: {text}\n"))
            }
            RequestError::TooLarge => Response::text(413, "text/plain", "request too large\n"),
            RequestError::Unsupported(text) => {
                Response::text(415, "text/plain", &format!("unsupported: {text}\n"))
            }
        }
    }
}

impl From<std::io::Error> for RequestError {
    fn from(_: std::io::Error) -> Self {
        RequestError::BadRequest("i/o error")
    }
}

fn read_request(
    stream: &mut TcpStream,
    peer: SocketAddr,
) -> std::result::Result<Request, RequestError> {
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    let header_end;
    loop {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Err(RequestError::BadRequest("connection closed"));
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = find_bytes(&buf, b"\r\n\r\n") {
            header_end = pos;
            break;
        }
        if buf.len() > MAX_HEADER_BYTES {
            return Err(RequestError::TooLarge);
        }
    }
    if header_end > MAX_HEADER_BYTES {
        return Err(RequestError::TooLarge);
    }
    let head = std::str::from_utf8(&buf[..header_end])
        .map_err(|_| RequestError::BadRequest("headers are not UTF-8"))?
        .to_string();
    let mut lines = head.split("\r\n");
    let request_line = lines
        .next()
        .ok_or(RequestError::BadRequest("missing request line"))?;
    let mut parts = request_line.split(' ');
    let method = parts
        .next()
        .filter(|m| !m.is_empty())
        .ok_or(RequestError::BadRequest("missing method"))?
        .to_string();
    let target = parts
        .next()
        .ok_or(RequestError::BadRequest("missing request target"))?
        .to_string();
    let version = parts
        .next()
        .ok_or(RequestError::BadRequest("missing HTTP version"))?;
    if parts.next().is_some() {
        return Err(RequestError::BadRequest("malformed request line"));
    }
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(RequestError::BadRequest(
            "only HTTP/1.0 and HTTP/1.1 are supported",
        ));
    }
    if !target.starts_with('/') || target.contains('\0') || target.contains('\\') {
        return Err(RequestError::BadRequest("invalid request target"));
    }

    let mut headers = HashMap::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (key, value) = line
            .split_once(':')
            .ok_or(RequestError::BadRequest("malformed header"))?;
        if key.len() > 64 || value.len() > 4096 {
            return Err(RequestError::TooLarge);
        }
        headers.insert(key.trim().to_ascii_lowercase(), value.trim().to_string());
        if headers.len() > 64 {
            return Err(RequestError::TooLarge);
        }
    }

    if method == "POST" && version == "HTTP/1.1" && !headers.contains_key("host") {
        return Err(RequestError::BadRequest("missing Host header"));
    }
    if let Some(encoding) = headers.get("transfer-encoding") {
        return Err(RequestError::BadRequest(if encoding.is_empty() {
            "invalid transfer encoding"
        } else {
            "chunked requests are not supported"
        }));
    }

    let length = match headers.get("content-length") {
        Some(value) => value
            .parse::<usize>()
            .map_err(|_| RequestError::BadRequest("invalid Content-Length"))?,
        None => 0,
    };
    let body_limit = if target.starts_with("/rules/import") {
        MAX_IMPORT_BYTES
    } else {
        MAX_BODY_BYTES
    };
    if length > body_limit {
        return Err(RequestError::TooLarge);
    }

    if length > 0 && method == "POST" {
        let content_type = headers
            .get("content-type")
            .map(String::as_str)
            .unwrap_or("");
        if !content_type
            .to_ascii_lowercase()
            .starts_with("application/x-www-form-urlencoded")
        {
            return Err(RequestError::Unsupported(
                "POST bodies must be application/x-www-form-urlencoded",
            ));
        }
    }

    let body_start = header_end + 4;
    while buf.len() < body_start + length {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Err(RequestError::BadRequest("body ended early"));
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > body_start + length {
            return Err(RequestError::TooLarge);
        }
    }
    let body = if length == 0 {
        String::new()
    } else {
        std::str::from_utf8(&buf[body_start..body_start + length])
            .map_err(|_| RequestError::BadRequest("body is not UTF-8"))?
            .to_string()
    };

    let (path, raw_query) = match target.split_once('?') {
        Some((path, query)) => (path.to_string(), query.to_string()),
        None => (target, String::new()),
    };
    if path.split('/').any(|part| part == ".." || part == ".") {
        return Err(RequestError::BadRequest("invalid path"));
    }

    Ok(Request {
        method,
        path,
        http11: version == "HTTP/1.1",
        headers,
        query: parse_form(&raw_query),
        form: parse_form(&body),
        peer,
    })
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn parse_form(raw: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for pair in raw.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = match pair.split_once('=') {
            Some((key, value)) => (key, value),
            None => (pair, ""),
        };
        out.insert(url_decode(key), url_decode(value));
    }
    out
}

fn url_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(byte) => {
                        out.push(byte);
                        i += 3;
                    }
                    Err(_) => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn host_allowed(request: &Request, bind: SocketAddr) -> bool {
    let Some(host) = request.headers.get("host") else {
        return !request.http11;
    };
    let name = strip_host_port(host);
    if bind.ip().is_loopback() {
        name == "localhost" || name == "127.0.0.1" || name == "::1" || name == bind.ip().to_string()
    } else if bind.ip().is_unspecified() {
        name == "localhost" || name.parse::<IpAddr>().is_ok()
    } else {
        name == bind.ip().to_string() || name == "localhost"
    }
}

fn strip_host_port(host: &str) -> &str {
    let host = host.trim();
    if let Some(rest) = host.strip_prefix('[')
        && let Some((inside, _)) = rest.split_once(']')
    {
        return inside;
    }
    if host.matches(':').count() == 1
        && let Some((name, port)) = host.rsplit_once(':')
        && port.parse::<u16>().is_ok()
    {
        return name;
    }
    host
}

// ------------------------------------------------------------------ response

struct Response {
    status: u16,
    content_type: &'static str,
    body: Vec<u8>,
    location: Option<String>,
    set_cookie: Option<String>,
}

impl Response {
    fn html(body: String) -> Response {
        Response::html_status(200, body)
    }

    fn html_status(status: u16, body: String) -> Response {
        Response {
            status,
            content_type: "text/html; charset=utf-8",
            body: body.into_bytes(),
            location: None,
            set_cookie: None,
        }
    }

    fn text(status: u16, content_type: &'static str, body: &str) -> Response {
        Response {
            status,
            content_type,
            body: body.as_bytes().to_vec(),
            location: None,
            set_cookie: None,
        }
    }

    fn json(value: serde_json::Value) -> Response {
        Response::text(
            200,
            "application/json; charset=utf-8",
            &serde_json::to_string(&value).unwrap_or_else(|_| "{}".into()),
        )
    }

    fn redirect(location: &str) -> Response {
        Response {
            status: 303,
            content_type: "text/plain; charset=utf-8",
            body: b"see other\n".to_vec(),
            location: Some(location.to_string()),
            set_cookie: None,
        }
    }

    fn with_cookie(mut self, cookie: String) -> Response {
        self.set_cookie = Some(cookie);
        self
    }

    fn error(status: u16, title: &str, detail: &str) -> Response {
        let body = format!(
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
             <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
             <title>{} — RustIPS</title><script src=\"/assets/theme.js\"></script>\
             <link rel=\"stylesheet\" href=\"/assets/app.css\"></head>\
             <body><main><section class=\"panel\"><h1>{}</h1><p>{}</p>\
             <p><a href=\"/\">Dashboard</a></p></section></main></body></html>",
            pages::esc(title),
            pages::esc(title),
            pages::esc(detail)
        );
        Response::html_status(status, body)
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        303 => "See Other",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        421 => "Misdirected Request",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Unknown",
    }
}

fn write_response(stream: &mut TcpStream, response: &Response) -> std::io::Result<()> {
    let mut head = format!(
        "HTTP/1.1 {} {}\r\n\
         Content-Type: {}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         Cache-Control: no-store\r\n\
         X-Content-Type-Options: nosniff\r\n\
         X-Frame-Options: DENY\r\n\
         Referrer-Policy: no-referrer\r\n\
         Content-Security-Policy: {}\r\n",
        response.status,
        reason(response.status),
        response.content_type,
        response.body.len(),
        CSP
    );
    if let Some(location) = &response.location {
        head.push_str(&format!("Location: {location}\r\n"));
    }
    if let Some(cookie) = &response.set_cookie {
        head.push_str(&format!("Set-Cookie: {cookie}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes())?;
    stream.write_all(&response.body)?;
    stream.flush()
}

// ------------------------------------------------------------------- routing

fn route(ctx: &Ctx, request: &Request) -> Response {
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/healthz") => healthz(ctx),
        ("GET", "/readyz") => readyz(ctx),
        ("GET", "/metrics") => {
            if ctx.bind.ip().is_loopback() {
                metrics(ctx)
            } else {
                Response::error(
                    403,
                    "Not available",
                    "Metrics are only exposed while the UI is bound to loopback.",
                )
            }
        }
        ("GET", "/assets/app.css") => Response::text(200, "text/css; charset=utf-8", CSS),
        ("GET", "/assets/country-colors.css") => country_colors_css(ctx),
        ("GET", "/assets/app.js") => {
            Response::text(200, "application/javascript; charset=utf-8", JS)
        }
        ("GET", "/assets/theme.js") => {
            Response::text(200, "application/javascript; charset=utf-8", THEME_JS)
        }
        ("GET", "/login") => {
            if session_of(ctx, request).is_some() {
                return Response::redirect("/");
            }
            let notice = request.param("notice").and_then(login_notice);
            login_page(ctx, None, notice)
        }
        ("POST", "/login") => do_login(ctx, request),
        _ => authenticated(ctx, request),
    }
}

// -------------------------------------------------------------------- session

enum Denied {
    Login,
    Csrf,
    Revalidated,
}

fn session_of(ctx: &Ctx, request: &Request) -> Option<(String, SessionView)> {
    let token = request.cookie(COOKIE)?;
    let view = ctx.sessions.touch(&token)?;
    Some((token, view))
}

fn check_session(
    ctx: &Ctx,
    request: &Request,
    require_csrf: bool,
    revalidate: bool,
) -> std::result::Result<(String, SessionView), Denied> {
    let (token, view) = session_of(ctx, request).ok_or(Denied::Login)?;

    if (view.needs_revalidation || revalidate) && !view.breakglass {
        if auth::revalidate(
            &ctx.cfg.web.pam_service,
            &view.user,
            &ctx.cfg.web.admin_group,
        ) {
            ctx.sessions.mark_validated(&token);
        } else {
            ctx.sessions.remove(&token);
            audit(
                ctx,
                &ModelActor::Admin(view.user.clone()),
                "session.revoked",
                &view.user,
                "account no longer valid or not in the admin group",
            );
            return Err(Denied::Revalidated);
        }
    }

    if require_csrf {
        let supplied = request
            .form
            .get("csrf")
            .map(String::as_str)
            .or_else(|| request.headers.get("x-csrf-token").map(String::as_str))
            .unwrap_or("");
        if !auth::constant_time_eq(supplied.as_bytes(), view.csrf.as_bytes()) {
            return Err(Denied::Csrf);
        }
    }

    Ok((token, view))
}

fn authenticated(ctx: &Ctx, request: &Request) -> Response {
    if request.method != "GET" && request.method != "POST" {
        return Response::error(405, "Method not allowed", "GET and POST only.");
    }
    let is_post = request.method == "POST";
    let (token, view) = match check_session(ctx, request, is_post, is_post) {
        Ok(value) => value,
        Err(Denied::Login) => return Response::redirect("/login"),
        Err(Denied::Revalidated) => {
            return Response::redirect("/login?notice=revalidated").with_cookie(clear_cookie());
        }
        Err(Denied::Csrf) => {
            return Response::error(
                403,
                "Request rejected",
                "The form token was missing or stale. Reload the page and try again.",
            );
        }
    };

    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/") => page_dashboard(ctx, &view),
        ("GET", "/detections") => page_detections(ctx, &view, request),
        ("GET", "/detectors") => page_detectors(ctx, &view, request),
        ("GET", "/logs") => page_logs(ctx, &view, request),
        ("GET", "/blocks") => page_blocks(ctx, &view, request),
        ("GET", "/firewall") => page_firewall(ctx, &view, request),
        ("GET", "/history") => page_history(ctx, &view),
        ("GET", "/strikes") => page_strikes(ctx, &view),
        ("GET", "/allowlist") => page_allowlist(ctx, &view, request),
        ("GET", "/rules") => page_rules(ctx, &view, request),
        ("GET", "/rules/new") => page_rule_new(ctx, &view),
        ("GET", "/rules/edit") => page_rule_edit(ctx, &view, request),
        ("GET", "/rules/history") => page_rule_history(ctx, &view, request),
        ("GET", "/rules/check") => page_rule_check(ctx, &view),
        ("GET", "/rules/export") => rules_export(ctx),
        ("GET", "/alerts") => page_alerts(ctx, &view, request),
        ("GET", "/alerts/target/new") => page_alert_target_new(ctx, &view),
        ("GET", "/alerts/target/edit") => page_alert_target_edit(ctx, &view, request),
        ("GET", "/settings") => page_settings(ctx, &view, request),
        ("GET", "/audit") => page_audit(ctx, &view),
        ("GET", "/api/summary") => api_summary(ctx),
        ("GET", "/api/system") => api_system(ctx, request),
        ("GET", "/api/ip") => api_ip(ctx, &view, request),
        ("GET", "/partial/detections") => partial_detections(ctx, &view, request),
        ("GET", "/partial/blocks") => partial_blocks(ctx, &view),
        ("POST", "/logout") => do_logout(ctx, &token, &view),
        ("POST", "/detectors/toggle") => do_detector_toggle(ctx, &view, request),
        ("POST", "/detectors/params") => do_detector_params(ctx, &view, request),
        ("POST", "/blocks/add") => do_block(ctx, &view, request),
        ("POST", "/blocks/remove") => do_unblock(ctx, &view, request),
        ("POST", "/firewall/toggle") => do_firewall_toggle(ctx, &view, request),
        ("POST", "/firewall/settings") => do_firewall_settings(ctx, &view, request),
        ("POST", "/firewall/admin/save") => do_firewall_admin_save(ctx, &view, request),
        ("POST", "/firewall/admin/delete") => do_firewall_admin_delete(ctx, &view, request),
        ("POST", "/firewall/admin/toggle") => do_firewall_admin_toggle(ctx, &view, request),
        ("POST", "/firewall/services/toggle") => do_firewall_service_toggle(ctx, &view, request),
        ("POST", "/firewall/services/ack") => do_firewall_services_ack(ctx, &view),
        ("POST", "/firewall/honeypot/port/add") => do_honeypot_port_add(ctx, &view, request),
        ("POST", "/firewall/honeypot/port/edit") => do_honeypot_port_edit(ctx, &view, request),
        ("POST", "/firewall/honeypot/port/delete") => do_honeypot_port_delete(ctx, &view, request),
        ("POST", "/allowlist/add") => do_allow_add(ctx, &view, request),
        ("POST", "/allowlist/remove") => do_allow_remove(ctx, &view, request),
        ("POST", "/rules/save") => do_rule_save(ctx, &view, request),
        ("POST", "/rules/toggle") => do_rule_toggle(ctx, &view, request),
        ("POST", "/rules/delete") => do_rule_delete(ctx, &view, request),
        ("POST", "/rules/import") => do_rule_import(ctx, &view, request),
        ("POST", "/rules/geo/check") => do_geo_check(ctx, &view),
        ("POST", "/rules/samples/geo") => do_load_geo_samples(ctx, &view),
        ("POST", "/alerts/requeue") => do_alert_requeue(ctx, &view, request),
        ("POST", "/alerts/delete") => do_alert_delete(ctx, &view, request),
        ("POST", "/alerts/clear") => do_alert_clear(ctx, &view),
        ("POST", "/alerts/test") => do_alert_test(ctx, &view),
        ("POST", "/alerts/target/save") => do_alert_target_save(ctx, &view, request),
        ("POST", "/alerts/target/delete") => do_alert_target_delete(ctx, &view, request),
        ("POST", "/alerts/settings") => do_alert_settings(ctx, &view, request),
        ("POST", "/settings/web") => do_settings(ctx, &view, request),
        ("POST", "/settings/reset") => do_settings_reset(ctx, &view),
        ("POST", "/settings/geo-colors") => do_country_color_save(ctx, &view, request),
        ("POST", "/settings/geo-colors/default") => do_country_default_save(ctx, &view, request),
        ("POST", "/settings/geo-colors/delete") => do_country_color_delete(ctx, &view, request),
        ("GET", _) | ("POST", _) => Response::error(404, "Not found", "No such page."),
        _ => Response::error(405, "Method not allowed", "GET and POST only."),
    }
}

fn geo_data(ctx: &Ctx) -> std::sync::RwLockReadGuard<'_, crate::geo::GeoData> {
    ctx.geo.read().unwrap_or_else(|poison| poison.into_inner())
}

fn page<'a>(ctx: &'a Ctx, view: &'a SessionView) -> pages::Page<'a> {
    pages::Page {
        user: &view.user,
        csrf: &view.csrf,
        breakglass: view.breakglass,
        mode: ctx.cfg.mode,
        bind: ctx.bind,
        version: &ctx.version,
    }
}

fn open_db(ctx: &Ctx) -> std::result::Result<Db, Response> {
    Db::open(&ctx.db_path).map_err(|e| {
        tracing::error!("web cannot open database: {e}");
        Response::error(
            500,
            "Database unavailable",
            "The state database could not be opened. Check the service log.",
        )
    })
}

fn audit(ctx: &Ctx, actor: &ModelActor, action: &str, subject: &str, detail: &str) {
    match Db::open(&ctx.db_path) {
        Ok(db) => {
            if let Err(e) = db.audit(actor, action, subject, detail) {
                tracing::warn!("audit write failed: {e}");
            }
        }
        Err(e) => tracing::warn!("audit open failed: {e}"),
    }
}

// --------------------------------------------------------------- login/logout

fn login_page(ctx: &Ctx, error: Option<&str>, notice: Option<&str>) -> Response {
    Response::html(pages::login(
        &ctx.version,
        &ctx.cfg.web.pam_service,
        auth::pam_service_file(&ctx.cfg.web.pam_service),
        error,
        notice,
    ))
}

fn login_notice(code: &str) -> Option<&'static str> {
    match code {
        "revalidated" => Some("Your session ended because the account is no longer authorised."),
        "logged_out" => Some("You have been logged out."),
        _ => None,
    }
}

fn do_login(ctx: &Ctx, request: &Request) -> Response {
    let user = request.param("user").unwrap_or("").trim().to_string();
    let password = request.param("pass").unwrap_or("");
    let token = request.param("token").unwrap_or("").trim().to_string();
    let source = net::normalise(request.peer.ip()).to_string();

    if user.is_empty() || user.len() > 64 || user.contains(['\0', '\n', '\r']) {
        return Response::html_status(
            400,
            login_page_body(ctx, Some("Enter a system username."), None),
        );
    }
    if password.len() > 1024 || token.len() > 1024 {
        return Response::html_status(
            400,
            login_page_body(ctx, Some("That input is too long."), None),
        );
    }

    // Break-glass is checked before the password limiter: a PAM outage plus a
    // few failed password attempts must never lock the recovery path out.
    if !token.is_empty() {
        if auth::verify_breakglass(&ctx.state_dir, &token) {
            ctx.limiter.record_success(&[
                format!("user:{}", user.to_lowercase()),
                format!("ip:{source}"),
            ]);
            audit(
                ctx,
                &ModelActor::Login(user.clone()),
                "login.success",
                &source,
                "break-glass token consumed",
            );
            return start_session(ctx, "break-glass", true);
        }
        ctx.limiter.record_failure(&[
            format!("user:{}", user.to_lowercase()),
            format!("ip:{source}"),
        ]);
        audit(
            ctx,
            &ModelActor::Login(user.clone()),
            "login.fail",
            &source,
            "break-glass token rejected",
        );
        return Response::html_status(
            401,
            login_page_body(ctx, Some("Invalid break-glass token."), None),
        );
    }

    let keys = vec![
        format!("user:{}", user.to_lowercase()),
        format!("ip:{source}"),
    ];
    if let Some(left) = ctx.limiter.locked_for(&keys) {
        let minutes = left.as_secs().div_ceil(60).max(1);
        audit(
            ctx,
            &ModelActor::Login(user.clone()),
            "login.locked",
            &source,
            "login limiter is active",
        );
        let text = format!("Too many failed attempts. Try again in {minutes} minute(s).");
        return Response::html_status(429, login_page_body(ctx, Some(&text), None));
    }

    match auth::authenticate(
        &ctx.cfg.web.pam_service,
        &user,
        password,
        &ctx.cfg.web.admin_group,
    ) {
        AuthOutcome::Success => {
            ctx.limiter.record_success(&keys);
            audit(
                ctx,
                &ModelActor::Login(user.clone()),
                "login.success",
                &source,
                "pam",
            );
            start_session(ctx, &user, false)
        }
        outcome => {
            ctx.limiter.record_failure(&keys);
            let result = outcome.audit_result();
            audit(
                ctx,
                &ModelActor::Login(user.clone()),
                "login.fail",
                &source,
                &result,
            );
            tracing::warn!(user = %user, %source, result = %result, "login rejected");
            Response::html_status(
                401,
                login_page_body(ctx, Some(outcome.user_message()), None),
            )
        }
    }
}

fn login_page_body(ctx: &Ctx, error: Option<&str>, notice: Option<&str>) -> String {
    // The login page builder returns a complete document; extract its body by
    // rendering it as the response body directly.
    pages::login(
        &ctx.version,
        &ctx.cfg.web.pam_service,
        auth::pam_service_file(&ctx.cfg.web.pam_service),
        error,
        notice,
    )
}

fn start_session(ctx: &Ctx, user: &str, breakglass: bool) -> Response {
    let (token, _csrf) = ctx.sessions.create(user, breakglass);
    Response::redirect("/").with_cookie(session_cookie(
        &token,
        ctx.cfg.web.session_absolute_mins.saturating_mul(60),
    ))
}

fn session_cookie(token: &str, max_age_secs: u64) -> String {
    format!("{COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age_secs}")
}

fn clear_cookie() -> String {
    format!("{COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0")
}

fn do_logout(ctx: &Ctx, token: &str, view: &SessionView) -> Response {
    ctx.sessions.remove(token);
    audit(
        ctx,
        &ModelActor::Admin(view.user.clone()),
        "logout",
        &view.user,
        "explicit logout",
    );
    Response::redirect("/login?notice=logged_out").with_cookie(clear_cookie())
}

// ------------------------------------------------------------------ dashboard

fn page_dashboard(ctx: &Ctx, view: &SessionView) -> Response {
    let db = match open_db(ctx) {
        Ok(db) => db,
        Err(response) => return response,
    };
    let now = Utc::now();
    let minute_ago = now - chrono::Duration::minutes(1);
    let hour_ago = now - chrono::Duration::hours(1);

    let recent = db.recent_detections(10).unwrap_or_default();
    let top_sources = db.top_sources(hour_ago, 5).unwrap_or_default();
    let top_ports = db.top_ports(hour_ago, 5).unwrap_or_default();
    let system_hour = db.system_samples_since(hour_ago).unwrap_or_default();
    let dash = pages::Dash {
        packets: ctx.stats.packets.load(Ordering::Relaxed),
        bytes: ctx.stats.bytes.load(Ordering::Relaxed),
        detections: db.detection_count().unwrap_or(0).max(0) as u64,
        detections_run: ctx.stats.detections.load(Ordering::Relaxed),
        blocks: ctx.stats.blocks.load(Ordering::Relaxed),
        active_blocks: db.active_block_count().unwrap_or(0),
        detections_last_min: db.detections_since(minute_ago).unwrap_or(0),
        blocks_last_min: db.blocks_since(minute_ago).unwrap_or(0),
        drops: ctx.stats.drops.load(Ordering::Relaxed),
        kernel_packets: ctx.stats.kernel_packets.load(Ordering::Relaxed),
        uptime_secs: ctx.started.elapsed().as_secs(),
        recent: &recent,
        top_sources: &top_sources,
        top_ports: &top_ports,
        system_hour: &system_hour,
    };
    let geo = geo_data(ctx);
    let body = pages::dashboard(&page(ctx, view), &dash, &geo);
    Response::html(body)
}

fn api_summary(ctx: &Ctx) -> Response {
    let (det_total, active, det_min, block_min, recent, sources, ports) =
        match Db::open(&ctx.db_path) {
            Ok(db) => {
                let now = Utc::now();
                (
                    db.detection_count().unwrap_or(0),
                    db.active_block_count().unwrap_or(0),
                    db.detections_since(now - chrono::Duration::minutes(1))
                        .unwrap_or(0),
                    db.blocks_since(now - chrono::Duration::minutes(1))
                        .unwrap_or(0),
                    db.recent_detections(10).unwrap_or_default(),
                    db.top_sources(now - chrono::Duration::hours(1), 5)
                        .unwrap_or_default(),
                    db.top_ports(now - chrono::Duration::hours(1), 5)
                        .unwrap_or_default(),
                )
            }
            Err(e) => {
                tracing::warn!("summary query failed: {e}");
                (0, 0, 0, 0, Vec::new(), Vec::new(), Vec::new())
            }
        };

    let alert_stats = Db::open(&ctx.db_path)
        .ok()
        .and_then(|db| db.alert_stats().ok())
        .unwrap_or_default();
    let alert_targets = Db::open(&ctx.db_path)
        .ok()
        .and_then(|db| db.list_alert_targets().ok())
        .map(|targets| targets.len())
        .unwrap_or(0);

    let geo = geo_data(ctx);
    let recent: Vec<serde_json::Value> = recent
        .iter()
        .map(|det| {
            serde_json::json!({
                "detector": det.detector.as_str(),
                "detector_title": det.detector.title(),
                "src": det.src.to_string(),
                "country": geo.lookup(det.src).country,
                "dst": det.dst.map(|d| d.to_string()),
                "dst_port": det.dst_port,
                "proto": det.proto.as_str(),
                "count": det.count,
                "window_secs": det.window_secs,
                "first_seen": det.first_seen,
                "last_seen": det.last_seen,
            })
        })
        .collect();
    let sources: Vec<serde_json::Value> = sources
        .into_iter()
        .map(|(src, count)| {
            let country = src
                .parse::<IpAddr>()
                .ok()
                .and_then(|ip| geo.lookup(ip).country);
            serde_json::json!([src, count, country])
        })
        .collect();

    Response::json(serde_json::json!({
        "version": ctx.version,
        "mode": ctx.cfg.mode.to_string(),
        "bind": ctx.bind.to_string(),
        "uptime_secs": ctx.started.elapsed().as_secs(),
        "packets": ctx.stats.packets.load(Ordering::Relaxed),
        "bytes": ctx.stats.bytes.load(Ordering::Relaxed),
        "detections": det_total,
        "detections_run": ctx.stats.detections.load(Ordering::Relaxed),
        "detections_suppressed": ctx.stats.detections_suppressed.load(Ordering::Relaxed),
        "blocks": ctx.stats.blocks.load(Ordering::Relaxed),
        "active_blocks": active,
        "detections_last_min": det_min,
        "blocks_last_min": block_min,
        "drops": ctx.stats.drops.load(Ordering::Relaxed),
        "kernel_packets": ctx.stats.kernel_packets.load(Ordering::Relaxed),
        "log_events_run": ctx.stats.log_events.load(Ordering::Relaxed),
        "log_dropped": ctx.stats.log_dropped.load(Ordering::Relaxed),
        "log_parse_errors": ctx.stats.log_parse_errors.load(Ordering::Relaxed),
        "alerts_pending": alert_stats.pending,
        "alerts_failed": alert_stats.failed,
        "alerts_sent": ctx.stats.alerts_sent.load(Ordering::Relaxed),
        "alerts_queued": ctx.stats.alerts_queued.load(Ordering::Relaxed),
        "alert_targets": alert_targets,
        "recent": recent,
        "top_sources": sources,
        "top_ports": ports,
    }))
}

fn country_colors_css(ctx: &Ctx) -> Response {
    let (colors, default) = Db::open(&ctx.db_path)
        .ok()
        .map(|db| (countries::load(&db), countries::load_default(&db)))
        .unwrap_or_else(|| (countries::CountryColors::new(), countries::default_color()));
    Response::text(
        200,
        "text/css; charset=utf-8",
        &countries::css(&colors, &default),
    )
}

fn api_system(ctx: &Ctx, request: &Request) -> Response {
    let hours = request
        .param("hours")
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(1)
        .clamp(1, 24);
    let since = Utc::now() - chrono::Duration::hours(hours as i64);
    let db = match open_db(ctx) {
        Ok(db) => db,
        Err(response) => return response,
    };
    let points = db.system_samples_since(since).unwrap_or_default();
    let compact = request.param("compact") == Some("1");
    let html = if compact {
        pages::system_graphs(&points, if hours == 1 { "hour" } else { "period" }, false)
    } else {
        pages::system_history(&points, hours)
    };
    Response::text(200, "text/html; charset=utf-8", &html)
}

fn api_ip(ctx: &Ctx, view: &SessionView, request: &Request) -> Response {
    let Some(raw) = request.param("ip") else {
        return Response::error(400, "Missing address", "Pass ?ip=203.0.113.7.");
    };
    let ip = match raw.trim().parse::<IpAddr>() {
        Ok(ip) => net::normalise(ip),
        Err(_) => return Response::error(400, "Invalid address", "That is not an IP address."),
    };
    let db = match open_db(ctx) {
        Ok(db) => db,
        Err(response) => return response,
    };
    let detections = db.detections_for_src(ip, 100).unwrap_or_default();
    let detection_total = db.detection_count_for_src(ip).unwrap_or(0);
    let blocks = db.blocks_for_src(ip, 100).unwrap_or_default();
    let block_total = db.block_count_for_src(ip).unwrap_or(0);
    let log_events = db.log_events_for_src(ip, 100).unwrap_or_default();
    let log_total = db.log_event_count_for_src(ip).unwrap_or(0);
    let strike = db.strike_for_src(ip).ok().flatten();
    let active_block = db.active_block(ip).ok().flatten();
    let allowlisted = db
        .list_allowlist()
        .unwrap_or_default()
        .into_iter()
        .find(|entry| {
            Cidr::parse(&entry.cidr)
                .map(|cidr| cidr.contains(ip))
                .unwrap_or(false)
        });
    let geo_info = {
        let data = ctx.geo.read().unwrap_or_else(|poison| poison.into_inner());
        data.lookup(ip)
    };
    let geo_loaded = {
        let data = ctx.geo.read().unwrap_or_else(|poison| poison.into_inner());
        !data.is_empty()
    };
    let html = pages::ip_history(
        &page(ctx, view),
        &pages::IpHistory {
            ip,
            country: geo_info.country.as_deref(),
            asn: geo_info.asn,
            geo_loaded,
            allowlisted: allowlisted.as_ref(),
            active_block: active_block.as_ref(),
            strike: strike.as_ref(),
            detections: &detections,
            detection_total,
            blocks: &blocks,
            block_total,
            log_events: &log_events,
            log_total,
            now: Utc::now(),
        },
    );
    Response::text(200, "text/html; charset=utf-8", &html)
}

fn readyz(ctx: &Ctx) -> Response {
    let db = Db::open_readonly(&ctx.db_path).ok();
    let database_ok = db.is_some();
    let journal = db
        .as_ref()
        .and_then(|db| db.log_state("journal.status").ok().flatten())
        .and_then(|value| {
            value
                .get("state")
                .and_then(|v| v.as_str())
                .map(str::to_string)
        })
        .unwrap_or_else(|| "unknown".into());
    let geo_loaded = {
        let data = ctx.geo.read().unwrap_or_else(|poison| poison.into_inner());
        !data.is_empty()
    };
    let nft_available = ctx.enforcer.available();
    let pam_ok =
        crate::auth::pam_loaded() && crate::auth::pam_service_file(&ctx.cfg.web.pam_service);
    let ready = database_ok && (ctx.cfg.mode != crate::config::Mode::Enforce || nft_available);
    Response::json(serde_json::json!({
        "ready": ready,
        "version": ctx.version,
        "mode": ctx.cfg.mode.to_string(),
        "checks": {
            "database": if database_ok { "ok" } else { "error" },
            "journal": journal,
            "geo": if geo_loaded { "loaded" } else { "absent" },
            "nftables": if nft_available { "available" } else { "missing" },
            "pam": if pam_ok { "ok" } else { "unavailable" },
            "alerts": {
                "pending": db.as_ref().and_then(|db| db.alert_stats().ok()).map(|s| s.pending).unwrap_or(0),
                "failed": db.as_ref().and_then(|db| db.alert_stats().ok()).map(|s| s.failed).unwrap_or(0),
            },
            "capture": {
                "packets": ctx.stats.packets.load(Ordering::Relaxed),
                "drops": ctx.stats.drops.load(Ordering::Relaxed),
            }
        }
    }))
}

fn healthz(ctx: &Ctx) -> Response {
    Response::json(serde_json::json!({
        "status": "ok",
        "version": ctx.version,
        "mode": ctx.cfg.mode.to_string(),
        "uptime_secs": ctx.started.elapsed().as_secs(),
        "bind": ctx.bind.to_string(),
    }))
}

fn metrics(ctx: &Ctx) -> Response {
    let db = Db::open_readonly(&ctx.db_path).ok();
    let active = db
        .as_ref()
        .and_then(|db| db.active_block_count().ok())
        .unwrap_or(0);
    let detections_total = db
        .as_ref()
        .and_then(|db| db.detection_count().ok())
        .unwrap_or(0);
    let alerts = db
        .as_ref()
        .and_then(|db| db.alert_stats().ok())
        .unwrap_or_default();
    let alert_targets = db
        .as_ref()
        .and_then(|db| db.list_alert_targets().ok())
        .map(|targets| targets.len())
        .unwrap_or(0);
    let body = format!(
        "# HELP rustips_packets_total Packets captured since start.\n\
         # TYPE rustips_packets_total counter\n\
         rustips_packets_total {}\n\
         # TYPE rustips_bytes_total counter\n\
         rustips_bytes_total {}\n\
         # TYPE rustips_detections_total counter\n\
         rustips_detections_total {}\n\
         # TYPE rustips_detections_stored Stored detection rows.\n\
         rustips_detections_stored {}\n\
         # TYPE rustips_detections_suppressed_total Detections suppressed by disabled detectors.\n\
         rustips_detections_suppressed_total {}\n\
         # TYPE rustips_blocks_active Current active blocks.\n\
         rustips_blocks_active {}\n\
         # TYPE rustips_capture_drops_total Capture drops reported by the kernel.\n\
         rustips_capture_drops_total {}\n\
         # TYPE rustips_capture_packets_total Packets delivered by the kernel.\n\
         rustips_capture_packets_total {}\n\
         # TYPE rustips_uptime_seconds Uptime.\n\
         rustips_uptime_seconds {}\n\
         # TYPE rustips_alerts_pending Pending webhook alerts.\n\
         rustips_alerts_pending {}\n\
         # TYPE rustips_alerts_failed Permanently failed webhook alerts.\n\
         rustips_alerts_failed {}\n\
         # TYPE rustips_alerts_sent_total Webhook alerts delivered since start.\n\
         rustips_alerts_sent_total {}\n\
         # TYPE rustips_alerts_queued_total Webhook alerts enqueued since start.\n\
         rustips_alerts_queued_total {}\n\
         # TYPE rustips_alert_targets Configured webhook targets.\n\
         rustips_alert_targets {}\n",
        ctx.stats.packets.load(Ordering::Relaxed),
        ctx.stats.bytes.load(Ordering::Relaxed),
        ctx.stats.detections.load(Ordering::Relaxed),
        detections_total,
        ctx.stats.detections_suppressed.load(Ordering::Relaxed),
        active,
        ctx.stats.drops.load(Ordering::Relaxed),
        ctx.stats.kernel_packets.load(Ordering::Relaxed),
        ctx.started.elapsed().as_secs(),
        alerts.pending,
        alerts.failed,
        ctx.stats.alerts_sent.load(Ordering::Relaxed),
        ctx.stats.alerts_queued.load(Ordering::Relaxed),
        alert_targets,
    );
    Response::text(200, "text/plain; version=0.0.4; charset=utf-8", &body)
}

// ------------------------------------------------------------------ detections

fn detector_filter(request: &Request) -> Option<String> {
    let value = request.param("detector").unwrap_or("").trim();
    if value.is_empty() {
        None
    } else if crate::model::Detector::ALL
        .iter()
        .any(|d| d.as_str() == value)
    {
        Some(value.to_string())
    } else {
        None
    }
}

fn page_number(request: &Request) -> u32 {
    request
        .param("page")
        .and_then(|p| p.parse::<u32>().ok())
        .unwrap_or(1)
        .max(1)
}

fn page_detections(ctx: &Ctx, view: &SessionView, request: &Request) -> Response {
    let db = match open_db(ctx) {
        Ok(db) => db,
        Err(response) => return response,
    };
    let detector = detector_filter(request);
    let page_no = page_number(request);
    let total = db
        .detection_count_filtered(detector.as_deref())
        .unwrap_or(0);
    let pages = ((total + PAGE_SIZE as i64 - 1) / PAGE_SIZE as i64).max(1) as u32;
    let page_no = page_no.min(pages);
    let offset = (page_no - 1) * PAGE_SIZE;
    let rows = db
        .detections_page(PAGE_SIZE, offset, detector.as_deref())
        .unwrap_or_default();
    let geo = geo_data(ctx);
    let body = pages::detections(
        &page(ctx, view),
        &rows,
        page_no,
        pages,
        total,
        detector.as_deref().unwrap_or(""),
        &geo,
    );
    Response::html(with_partial(body, detector.as_deref(), page_no))
}

/// Add the `data-partial` attribute to `<body>` without another copy of the
/// layout. The attribute is a fixed, server-built path.
fn with_partial(html: String, detector: Option<&str>, page_no: u32) -> String {
    let partial = match detector {
        Some(detector) => format!(
            "/partial/detections?detector={}&page={page_no}",
            pages::esc(detector)
        ),
        None => format!("/partial/detections?page={page_no}"),
    };
    html.replacen(
        "<body data-live=\"1\">",
        &format!("<body data-live=\"1\" data-partial=\"{partial}\">"),
        1,
    )
}

fn partial_detections(ctx: &Ctx, view: &SessionView, request: &Request) -> Response {
    let db = match open_db(ctx) {
        Ok(db) => db,
        Err(response) => return response,
    };
    let detector = detector_filter(request);
    let page_no = page_number(request);
    let offset = (page_no - 1) * PAGE_SIZE;
    let rows = db
        .detections_page(PAGE_SIZE, offset, detector.as_deref())
        .unwrap_or_default();
    let geo = geo_data(ctx);
    Response::html(pages::detection_rows(&page(ctx, view), &rows, &geo))
}

// ------------------------------------------------------------------ detectors

fn page_detectors(ctx: &Ctx, view: &SessionView, request: &Request) -> Response {
    let db = match open_db(ctx) {
        Ok(db) => db,
        Err(response) => return response,
    };
    let disabled = db.disabled_detectors().unwrap_or_default();
    let overrides = db.detection_overrides().unwrap_or_default();
    let notice = request
        .param("notice")
        .and_then(notice_text)
        .map(str::to_string);
    Response::html(pages::detectors(
        &page(ctx, view),
        &ctx.cfg,
        &disabled,
        &overrides,
        notice.as_deref(),
    ))
}

fn do_detector_toggle(ctx: &Ctx, view: &SessionView, request: &Request) -> Response {
    let Some(id) = request.param("id").and_then(|value| {
        crate::model::Detector::ALL
            .into_iter()
            .find(|detector| detector.as_str() == value)
    }) else {
        return Response::redirect("/detectors?notice=detector_missing");
    };
    let enable = request.param("enable") == Some("yes");
    let db = match open_db(ctx) {
        Ok(db) => db,
        Err(response) => return response,
    };
    if let Err(e) = db.set_detector_enabled(id, enable) {
        return Response::error(500, "Detector unchanged", &e.to_string());
    }
    audit(
        ctx,
        &ModelActor::Admin(view.user.clone()),
        if enable {
            "detector.enable"
        } else {
            "detector.disable"
        },
        id.as_str(),
        if enable {
            "detection enabled"
        } else {
            "detection disabled"
        },
    );
    Response::redirect(if enable {
        "/detectors?notice=detector_enabled"
    } else {
        "/detectors?notice=detector_disabled"
    })
}

fn do_detector_params(ctx: &Ctx, view: &SessionView, request: &Request) -> Response {
    let db = match open_db(ctx) {
        Ok(db) => db,
        Err(response) => return response,
    };
    let action = request.param("action").unwrap_or("save");
    let return_settings = request.param("return") == Some("settings");
    let return_firewall = request.param("return") == Some("firewall");
    let back = if return_settings {
        "/settings"
    } else if return_firewall {
        "/firewall?tab=honeypot"
    } else {
        "/detectors"
    };
    let back_url = |notice: &str| {
        if back.contains('?') {
            format!("{back}&notice={notice}")
        } else {
            format!("{back}?notice={notice}")
        }
    };
    let honeypot_form = request.param("scope") == Some("honeypot");

    if action == "reset_all" {
        if let Err(e) = db.clear_all_detection_overrides() {
            return Response::error(500, "Parameters unchanged", &e.to_string());
        }
        audit(
            ctx,
            &ModelActor::Admin(view.user.clone()),
            "detection.params.reset",
            "all",
            "cleared every stored detection parameter override",
        );
        return Response::redirect(&back_url("params_reset_all"));
    }

    if let Some(key) = request.param("reset_key") {
        if crate::params::spec(key).is_none() {
            return Response::error(400, "Unknown parameter", "That parameter is not editable.");
        }
        let mut merged = db.detection_overrides().unwrap_or_default();
        merged.remove(key);
        let mut candidate = ctx.baseline.clone();
        if let Err(e) = crate::params::apply_overrides(&mut candidate, &merged) {
            return Response::error(
                400,
                "Reset rejected",
                &format!("Resetting {key} would leave an invalid configuration: {e}"),
            );
        }
        if let Err(e) = db.clear_detection_overrides(&[key.to_string()]) {
            return Response::error(500, "Parameter unchanged", &e.to_string());
        }
        audit(
            ctx,
            &ModelActor::Admin(view.user.clone()),
            "detection.params.reset",
            key,
            "reset to the built-in default",
        );
        let notice = if honeypot_form {
            "honeypot_reset"
        } else {
            "params_reset"
        };
        return Response::redirect(&back_url(notice));
    }

    let scope = request.param("scope").unwrap_or("");
    let keys = crate::params::keys_for(scope);
    if keys.is_empty() {
        return Response::error(
            400,
            "Unknown parameter group",
            "The form did not name a known detector or shared group.",
        );
    }

    if action == "reset_scope" {
        let keys: Vec<String> = keys.iter().map(|key| (*key).to_string()).collect();
        let mut merged = db.detection_overrides().unwrap_or_default();
        for key in &keys {
            merged.remove(key);
        }
        let mut candidate = ctx.baseline.clone();
        if let Err(e) = crate::params::apply_overrides(&mut candidate, &merged) {
            return Response::error(
                400,
                "Reset rejected",
                &format!("Resetting this group would leave an invalid configuration: {e}"),
            );
        }
        if let Err(e) = db.clear_detection_overrides(&keys) {
            return Response::error(500, "Parameters unchanged", &e.to_string());
        }
        audit(
            ctx,
            &ModelActor::Admin(view.user.clone()),
            "detection.params.reset",
            scope,
            &format!("reset {} parameter(s) to built-in defaults", keys.len()),
        );
        let notice = if scope == "honeypot" {
            "honeypot_reset"
        } else {
            "params_reset_scope"
        };
        return Response::redirect(&back_url(notice));
    }

    let mut changes = std::collections::BTreeMap::new();
    let mut seen = 0_usize;
    for key in keys {
        let Some(raw) = request.form.get(&format!("p:{key}")) else {
            continue;
        };
        seen += 1;
        let Some(spec) = crate::params::spec(key) else {
            return Response::error(400, "Unknown parameter", "That parameter is not editable.");
        };
        let normalized = match crate::params::normalize(spec, raw) {
            Ok(value) => value,
            Err(message) => {
                return Response::error(400, "Parameter rejected", &message);
            }
        };
        // Leave unchanged fields alone so saving one field does not create
        // overrides for every key in the group. A value that differs from the
        // running configuration is stored even if it equals the built-in
        // default, because the config file may have customised it.
        if normalized != crate::params::value(&ctx.cfg, key) {
            changes.insert(key.to_string(), normalized);
        }
    }
    if seen == 0 {
        return Response::error(
            400,
            "No parameters",
            "The form contained no editable detector parameters.",
        );
    }
    let mut merged = db.detection_overrides().unwrap_or_default();
    merged.extend(changes.clone());
    let mut candidate = ctx.baseline.clone();
    if let Err(e) = crate::params::apply_overrides(&mut candidate, &merged) {
        return Response::error(400, "Parameter rejected", &e);
    }
    if let Err(e) = db.set_detection_overrides(&changes, &[]) {
        return Response::error(500, "Parameters unchanged", &e.to_string());
    }
    audit(
        ctx,
        &ModelActor::Admin(view.user.clone()),
        "detection.params.save",
        scope,
        &format!("{} override(s) stored; restart required", changes.len()),
    );
    let notice = if scope == "honeypot" {
        "honeypot_saved"
    } else {
        "params_saved"
    };
    Response::redirect(&back_url(notice))
}

// ------------------------------------------------------------------ firewall

fn firewall_effective_config(ctx: &Ctx, db: &Db) -> std::result::Result<Config, String> {
    let overrides = db.detection_overrides().map_err(|e| e.to_string())?;
    let mut effective = ctx.baseline.clone();
    crate::params::apply_overrides(&mut effective, &overrides)?;
    Ok(effective)
}

fn page_firewall(ctx: &Ctx, view: &SessionView, request: &Request) -> Response {
    let db = match open_db(ctx) {
        Ok(db) => db,
        Err(response) => return response,
    };
    let tab = match request.param("tab").unwrap_or("active") {
        "permanent" => "permanent",
        "admin" => "admin",
        "external" | "services" => "external",
        "internal" => "internal",
        "honeypot" => "honeypot",
        _ => "active",
    };
    let settings = firewall::settings(&db, &ctx.cfg);
    let (listening, discovery_error) = match firewall::discover() {
        Ok(sockets) => {
            let rows: Vec<(String, u16, Option<IpAddr>)> = sockets
                .iter()
                .map(|socket| (socket.proto.as_str().to_string(), socket.port, socket.addr))
                .collect();
            if let Err(e) = db.upsert_firewall_services(&rows, Utc::now()) {
                tracing::warn!(error = %e, "cannot record discovered services");
            }
            (sockets, None)
        }
        Err(e) => (Vec::new(), Some(e.to_string())),
    };
    let service_states = db.firewall_services().unwrap_or_default();
    let admin_rules = db.firewall_admin_rules().unwrap_or_default();
    let all_blocks = db.list_active_blocks().unwrap_or_default();
    let active_blocks: Vec<crate::model::Block> = all_blocks
        .iter()
        .filter(|block| !block.is_permanent())
        .cloned()
        .collect();
    let permanent_blocks: Vec<crate::model::Block> = all_blocks
        .into_iter()
        .filter(|block| block.is_permanent())
        .collect();
    let overrides = db.detection_overrides().unwrap_or_default();
    let effective = {
        let mut cfg = ctx.baseline.clone();
        let _ = crate::params::apply_overrides(&mut cfg, &overrides);
        cfg
    };
    let plan = firewall::plan(
        &settings,
        &effective.detection,
        &listening,
        &admin_rules,
        &service_states,
    );
    let edit_admin = request
        .param("edit")
        .and_then(|value| value.parse::<i64>().ok())
        .and_then(|id| admin_rules.iter().find(|rule| rule.id == id));
    let notice = request
        .param("notice")
        .and_then(notice_text)
        .map(str::to_string);
    let geo = geo_data(ctx);
    let html = pages::firewall(
        &page(ctx, view),
        &pages::FirewallView {
            tab,
            settings: &settings,
            plan: &plan,
            listening: &listening,
            service_states: &service_states,
            admin_rules: &admin_rules,
            edit_admin,
            active_blocks: &active_blocks,
            permanent_blocks: &permanent_blocks,
            cfg: &effective,
            detection_overrides: &overrides,
            honeypot_enabled: effective.detection.honeypot_enabled,
            honeypot_ports: &effective.detection.honeypot_ports,
            honeypot_hits: effective.detection.honeypot_hits,
            geo: &geo,
            discovery_error: discovery_error.as_deref(),
            notice: notice.as_deref(),
        },
    );
    let html = if tab == "active" {
        html.replacen(
            "<body data-live=\"1\">",
            "<body data-live=\"1\" data-partial=\"/partial/blocks\">",
            1,
        )
    } else {
        html
    };
    Response::html(html)
}

fn do_firewall_toggle(ctx: &Ctx, view: &SessionView, request: &Request) -> Response {
    let db = match open_db(ctx) {
        Ok(db) => db,
        Err(response) => return response,
    };
    let mut settings = firewall::settings(&db, &ctx.cfg);
    let enable = request.param("enable") == Some("yes");
    settings.enabled = enable;
    if let Err(e) = firewall::save_settings(&db, &settings) {
        return Response::error(500, "Firewall unchanged", &e.to_string());
    }
    audit(
        ctx,
        &ModelActor::Admin(view.user.clone()),
        if enable {
            "firewall.enable"
        } else {
            "firewall.disable"
        },
        "service firewall",
        if enable {
            "service allow rules and default-deny enabled"
        } else {
            "service firewall disabled; blocked-source rules remain"
        },
    );
    Response::redirect(if enable {
        "/firewall?notice=firewall_enabled"
    } else {
        "/firewall?notice=firewall_disabled"
    })
}

fn do_firewall_settings(ctx: &Ctx, view: &SessionView, request: &Request) -> Response {
    let db = match open_db(ctx) {
        Ok(db) => db,
        Err(response) => return response,
    };
    let mut settings = firewall::settings(&db, &ctx.cfg);
    let refresh = match request
        .param("refresh_secs")
        .and_then(|value| value.trim().parse::<u64>().ok())
    {
        Some(value) if (1..=86_400).contains(&value) => value,
        _ => {
            return Response::error(
                400,
                "Firewall settings rejected",
                "Refresh must be 1..=86400 seconds.",
            );
        }
    };
    let allow_tcp = match parse_firewall_ports(request.param("allow_tcp_ports").unwrap_or("")) {
        Ok(ports) => ports,
        Err(e) => return Response::error(400, "Firewall settings rejected", &e),
    };
    let allow_udp = match parse_firewall_ports(request.param("allow_udp_ports").unwrap_or("")) {
        Ok(ports) => ports,
        Err(e) => return Response::error(400, "Firewall settings rejected", &e),
    };

    settings.discover_services = form_bool(request, "discover_services");
    settings.refresh_secs = refresh;
    settings.allow_tcp_ports = allow_tcp;
    settings.allow_udp_ports = allow_udp;
    settings.include_honeypot = form_bool(request, "include_honeypot");
    settings.log_drops = form_bool(request, "log_drops");
    settings.reject = form_bool(request, "reject");
    if let Err(e) = firewall::save_settings(&db, &settings) {
        return Response::error(500, "Firewall unchanged", &e.to_string());
    }
    audit(
        ctx,
        &ModelActor::Admin(view.user.clone()),
        "firewall.settings",
        "service firewall",
        &format!(
            "discover={} refresh={}s tcp={:?} udp={:?} honeypot={} log_drops={} reject={}",
            settings.discover_services,
            settings.refresh_secs,
            settings.allow_tcp_ports,
            settings.allow_udp_ports,
            settings.include_honeypot,
            settings.log_drops,
            settings.reject
        ),
    );
    Response::redirect("/firewall?notice=firewall_saved")
}

fn form_bool(request: &Request, name: &str) -> bool {
    request.param(name).is_some_and(|value| {
        matches!(
            value.to_ascii_lowercase().as_str(),
            "true" | "yes" | "on" | "1"
        )
    })
}

fn parse_firewall_ports(raw: &str) -> std::result::Result<Vec<u16>, String> {
    let mut ports = Vec::new();
    for item in raw.split(',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        let port: u16 = item
            .parse()
            .map_err(|_| format!("{item:?} is not a port (1..=65535)"))?;
        if port == 0 {
            return Err("ports must be 1..=65535".into());
        }
        if !ports.contains(&port) {
            ports.push(port);
        }
    }
    ports.sort_unstable();
    Ok(ports)
}

fn parse_optional_cidr(value: &str) -> std::result::Result<Option<String>, String> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    Cidr::parse(value)
        .map(|cidr| Some(cidr.to_string()))
        .map_err(|e| format!("{value:?}: {e}"))
}

fn do_firewall_admin_save(ctx: &Ctx, view: &SessionView, request: &Request) -> Response {
    let db = match open_db(ctx) {
        Ok(db) => db,
        Err(response) => return response,
    };
    let id = match request.param("id").unwrap_or("0").trim().parse::<i64>() {
        Ok(id) if id >= 0 => id,
        _ => return Response::error(400, "Admin drop rejected", "Invalid rule ID."),
    };
    let src = match parse_optional_cidr(request.param("src").unwrap_or("")) {
        Ok(src) => src,
        Err(e) => return Response::error(400, "Admin drop rejected", &e),
    };
    let dst = match parse_optional_cidr(request.param("dst").unwrap_or("")) {
        Ok(dst) => dst,
        Err(e) => return Response::error(400, "Admin drop rejected", &e),
    };
    if let (Some(src), Some(dst)) = (&src, &dst) {
        let src = Cidr::parse(src).ok();
        let dst = Cidr::parse(dst).ok();
        if let (Some(src), Some(dst)) = (src, dst)
            && src.addr.is_ipv4() != dst.addr.is_ipv4()
        {
            return Response::error(
                400,
                "Admin drop rejected",
                "Source and destination must be the same address family.",
            );
        }
    }
    let proto = match request
        .param("proto")
        .unwrap_or("any")
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "any" | "" => "any",
        "tcp" => "tcp",
        "udp" => "udp",
        "icmp" => "icmp",
        "icmp6" | "icmpv6" => "icmp6",
        _ => {
            return Response::error(
                400,
                "Admin drop rejected",
                "Protocol must be any, tcp, udp, icmp or icmp6.",
            );
        }
    };
    let port = match request.param("port").unwrap_or("").trim() {
        "" => None,
        value => match value.parse::<u16>() {
            Ok(port) if port > 0 => Some(port),
            _ => {
                return Response::error(
                    400,
                    "Admin drop rejected",
                    "Port must be 1..=65535 or blank.",
                );
            }
        },
    };
    if port.is_some() && !matches!(proto, "tcp" | "udp") {
        return Response::error(
            400,
            "Admin drop rejected",
            "A port can only be used with TCP or UDP.",
        );
    }
    let enabled = form_bool(request, "enabled");
    let saved = match db.save_firewall_admin_rule(
        id,
        src.as_deref(),
        dst.as_deref(),
        proto,
        port,
        enabled,
        &view.user,
    ) {
        Ok(saved) => saved,
        Err(e) => return Response::error(500, "Admin drop unchanged", &e.to_string()),
    };
    audit(
        ctx,
        &ModelActor::Admin(view.user.clone()),
        if id == 0 {
            "firewall.admin.create"
        } else {
            "firewall.admin.update"
        },
        &saved.to_string(),
        &format!(
            "src={} dst={} proto={} port={} enabled={}",
            src.as_deref().unwrap_or("any"),
            dst.as_deref().unwrap_or("any"),
            proto,
            port.map(|port| port.to_string())
                .unwrap_or_else(|| "any".into()),
            enabled
        ),
    );
    Response::redirect("/firewall?tab=admin&notice=admin_rule_saved")
}

fn do_firewall_admin_delete(ctx: &Ctx, view: &SessionView, request: &Request) -> Response {
    let Some(id) = request
        .param("id")
        .and_then(|value| value.parse::<i64>().ok())
    else {
        return Response::redirect("/firewall?tab=admin&notice=admin_rule_missing");
    };
    let db = match open_db(ctx) {
        Ok(db) => db,
        Err(response) => return response,
    };
    match db.delete_firewall_admin_rule(id) {
        Ok(true) => {
            audit(
                ctx,
                &ModelActor::Admin(view.user.clone()),
                "firewall.admin.delete",
                &id.to_string(),
                "admin drop rule deleted",
            );
            Response::redirect("/firewall?tab=admin&notice=admin_rule_deleted")
        }
        Ok(false) => Response::redirect("/firewall?tab=admin&notice=admin_rule_missing"),
        Err(e) => Response::error(500, "Admin drop unchanged", &e.to_string()),
    }
}

fn do_firewall_admin_toggle(ctx: &Ctx, view: &SessionView, request: &Request) -> Response {
    let Some(id) = request
        .param("id")
        .and_then(|value| value.parse::<i64>().ok())
    else {
        return Response::redirect("/firewall?tab=admin&notice=admin_rule_missing");
    };
    let enable = request.param("enable") == Some("yes");
    let db = match open_db(ctx) {
        Ok(db) => db,
        Err(response) => return response,
    };
    match db.set_firewall_admin_rule_enabled(id, enable, &view.user) {
        Ok(true) => {
            audit(
                ctx,
                &ModelActor::Admin(view.user.clone()),
                if enable {
                    "firewall.admin.enable"
                } else {
                    "firewall.admin.disable"
                },
                &id.to_string(),
                "admin drop rule state changed",
            );
            Response::redirect(if enable {
                "/firewall?tab=admin&notice=admin_rule_enabled"
            } else {
                "/firewall?tab=admin&notice=admin_rule_disabled"
            })
        }
        Ok(false) => Response::redirect("/firewall?tab=admin&notice=admin_rule_missing"),
        Err(e) => Response::error(500, "Admin drop unchanged", &e.to_string()),
    }
}

fn do_firewall_service_toggle(ctx: &Ctx, view: &SessionView, request: &Request) -> Response {
    let proto = match request.param("proto").unwrap_or("") {
        "tcp" => "tcp",
        "udp" => "udp",
        _ => return Response::redirect("/firewall?tab=services&notice=service_missing"),
    };
    let Some(port) = request
        .param("port")
        .and_then(|value| value.parse::<u16>().ok())
    else {
        return Response::redirect("/firewall?tab=services&notice=service_missing");
    };
    let addr = request
        .param("addr")
        .and_then(|value| value.trim().parse::<IpAddr>().ok());
    let drop = request.param("drop") == Some("yes");
    let db = match open_db(ctx) {
        Ok(db) => db,
        Err(response) => return response,
    };
    match db.set_firewall_service_dropped(proto, port, addr, drop) {
        Ok(true) => {
            audit(
                ctx,
                &ModelActor::Admin(view.user.clone()),
                if drop {
                    "firewall.service.drop"
                } else {
                    "firewall.service.allow"
                },
                &format!("{proto}/{port}"),
                &format!(
                    "addr={} dropped={drop}",
                    addr.map(|addr| addr.to_string())
                        .unwrap_or_else(|| "any".into())
                ),
            );
            Response::redirect(if drop {
                "/firewall?tab=services&notice=service_dropped"
            } else {
                "/firewall?tab=services&notice=service_allowed"
            })
        }
        Ok(false) => Response::redirect("/firewall?tab=services&notice=service_missing"),
        Err(e) => Response::error(500, "Service unchanged", &e.to_string()),
    }
}

fn do_firewall_services_ack(ctx: &Ctx, view: &SessionView) -> Response {
    let db = match open_db(ctx) {
        Ok(db) => db,
        Err(response) => return response,
    };
    match db.acknowledge_firewall_services() {
        Ok(count) => {
            audit(
                ctx,
                &ModelActor::Admin(view.user.clone()),
                "firewall.services.ack",
                "",
                &format!("{count} service row(s) marked as seen"),
            );
            Response::redirect("/firewall?tab=services&notice=services_acknowledged")
        }
        Err(e) => Response::error(500, "Services unchanged", &e.to_string()),
    }
}

fn save_honeypot_ports(ctx: &Ctx, db: &Db, ports: &[u16]) -> std::result::Result<(), String> {
    let key = "detection.honeypot_ports";
    let spec = crate::params::spec(key).ok_or_else(|| "unknown parameter".to_string())?;
    let raw = ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let normalized = crate::params::normalize(spec, &raw)?;
    let mut overrides = db.detection_overrides().map_err(|e| e.to_string())?;
    overrides.insert(key.to_string(), normalized.clone());
    let mut candidate = ctx.baseline.clone();
    crate::params::apply_overrides(&mut candidate, &overrides)?;
    let mut changes = std::collections::BTreeMap::new();
    changes.insert(key.to_string(), normalized);
    db.set_detection_overrides(&changes, &[])
        .map_err(|e| e.to_string())
}

fn do_honeypot_port_add(ctx: &Ctx, view: &SessionView, request: &Request) -> Response {
    let Some(port) = request
        .param("port")
        .and_then(|value| value.trim().parse::<u16>().ok())
        .filter(|port| *port > 0)
    else {
        return Response::redirect("/firewall?tab=honeypot&notice=honeypot_port_invalid");
    };
    let db = match open_db(ctx) {
        Ok(db) => db,
        Err(response) => return response,
    };
    let mut ports = match firewall_effective_config(ctx, &db) {
        Ok(cfg) => cfg.detection.honeypot_ports,
        Err(e) => return Response::error(500, "Honeypot unchanged", &e),
    };
    if ports.contains(&port) {
        return Response::redirect("/firewall?tab=honeypot&notice=honeypot_port_duplicate");
    }
    ports.push(port);
    ports.sort_unstable();
    if let Err(e) = save_honeypot_ports(ctx, &db, &ports) {
        return Response::error(400, "Honeypot unchanged", &e);
    }
    audit(
        ctx,
        &ModelActor::Admin(view.user.clone()),
        "firewall.honeypot.port.add",
        &port.to_string(),
        "honeypot port added; DET-26 restart required, firewall allow set updates live",
    );
    Response::redirect("/firewall?tab=honeypot&notice=honeypot_port_saved")
}

fn do_honeypot_port_delete(ctx: &Ctx, view: &SessionView, request: &Request) -> Response {
    let Some(port) = request
        .param("port")
        .and_then(|value| value.parse::<u16>().ok())
    else {
        return Response::redirect("/firewall?tab=honeypot&notice=honeypot_port_invalid");
    };
    let db = match open_db(ctx) {
        Ok(db) => db,
        Err(response) => return response,
    };
    let mut ports = match firewall_effective_config(ctx, &db) {
        Ok(cfg) => cfg.detection.honeypot_ports,
        Err(e) => return Response::error(500, "Honeypot unchanged", &e),
    };
    if !ports.contains(&port) {
        return Response::redirect("/firewall?tab=honeypot&notice=honeypot_port_missing");
    }
    ports.retain(|existing| *existing != port);
    if let Err(e) = save_honeypot_ports(ctx, &db, &ports) {
        return Response::error(400, "Honeypot unchanged", &e);
    }
    audit(
        ctx,
        &ModelActor::Admin(view.user.clone()),
        "firewall.honeypot.port.delete",
        &port.to_string(),
        "honeypot port removed; DET-26 restart required, firewall allow set updates live",
    );
    Response::redirect("/firewall?tab=honeypot&notice=honeypot_port_saved")
}

fn do_honeypot_port_edit(ctx: &Ctx, view: &SessionView, request: &Request) -> Response {
    let old = request
        .param("old")
        .and_then(|value| value.parse::<u16>().ok());
    let new = request
        .param("new")
        .and_then(|value| value.trim().parse::<u16>().ok())
        .filter(|port| *port > 0);
    let (Some(old), Some(new)) = (old, new) else {
        return Response::redirect("/firewall?tab=honeypot&notice=honeypot_port_invalid");
    };
    let db = match open_db(ctx) {
        Ok(db) => db,
        Err(response) => return response,
    };
    let mut ports = match firewall_effective_config(ctx, &db) {
        Ok(cfg) => cfg.detection.honeypot_ports,
        Err(e) => return Response::error(500, "Honeypot unchanged", &e),
    };
    if !ports.contains(&old) {
        return Response::redirect("/firewall?tab=honeypot&notice=honeypot_port_missing");
    }
    if old != new && ports.contains(&new) {
        return Response::redirect("/firewall?tab=honeypot&notice=honeypot_port_duplicate");
    }
    for port in &mut ports {
        if *port == old {
            *port = new;
        }
    }
    ports.sort_unstable();
    ports.dedup();
    if let Err(e) = save_honeypot_ports(ctx, &db, &ports) {
        return Response::error(400, "Honeypot unchanged", &e);
    }
    audit(
        ctx,
        &ModelActor::Admin(view.user.clone()),
        "firewall.honeypot.port.edit",
        &new.to_string(),
        &format!("honeypot port {old} changed to {new}; DET-26 restart required"),
    );
    Response::redirect("/firewall?tab=honeypot&notice=honeypot_port_saved")
}

// ---------------------------------------------------------------------- logs

fn page_logs(ctx: &Ctx, view: &SessionView, request: &Request) -> Response {
    let db = match open_db(ctx) {
        Ok(db) => db,
        Err(response) => return response,
    };
    let origin = request
        .param("origin")
        .filter(|value| *value == "journal" || *value == "file");
    let search = request
        .param("q")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.chars().take(120).collect::<String>());
    let total = db.log_event_count(origin, search.as_deref()).unwrap_or(0);
    let pages = ((total + PAGE_SIZE as i64 - 1) / PAGE_SIZE as i64).max(1) as u32;
    let page_no = page_number(request).min(pages);
    let offset = (page_no - 1) * PAGE_SIZE;
    let rows = db
        .log_events_page(PAGE_SIZE, offset, origin, search.as_deref())
        .unwrap_or_default();
    let journal = db.log_state("journal.status").ok().flatten();
    let gap = db.log_state("journal.gap").ok().flatten();
    let pruned = db
        .log_state("log.pruned")
        .ok()
        .flatten()
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let status = pages::LogStatus {
        journal: journal.as_ref(),
        gap: gap.as_ref(),
        events_run: ctx.stats.log_events.load(Ordering::Relaxed),
        dropped: ctx.stats.log_dropped.load(Ordering::Relaxed),
        parse_errors: ctx.stats.log_parse_errors.load(Ordering::Relaxed),
        pruned,
    };
    let geo = geo_data(ctx);
    Response::html(pages::logs(
        &page(ctx, view),
        &rows,
        page_no,
        pages,
        total,
        origin.unwrap_or(""),
        search.as_deref().unwrap_or(""),
        &status,
        &geo,
    ))
}

// ---------------------------------------------------------------------- rules

fn rule_form_from_request(request: &Request) -> RuleForm {
    let text = |name: &str| request.param(name).unwrap_or("").trim().to_string();
    RuleForm {
        id: text("id").parse().unwrap_or(0),
        name: text("name"),
        description: text("description"),
        enabled: request.param("enabled").is_some(),
        priority: text("priority"),
        severity: text("severity"),
        dry_run: request.param("dry_run").is_some(),
        detectors: text("detectors"),
        sources: text("sources"),
        not_sources: text("not_sources"),
        ports: text("ports"),
        protocols: text("protocols"),
        min_count: text("min_count"),
        min_strikes: text("min_strikes"),
        only_if_blocked: request.param("only_if_blocked").is_some(),
        last_seen_within: text("last_seen_within"),
        tags: text("tags"),
        countries: text("countries"),
        not_countries: text("not_countries"),
        asns: text("asns"),
        not_asns: text("not_asns"),
        days: text("days"),
        start: text("start"),
        end: text("end"),
        action: text("action"),
        duration: text("duration"),
        tag: text("tag"),
        ladder: text("ladder"),
    }
}

fn page_rules(ctx: &Ctx, view: &SessionView, request: &Request) -> Response {
    let db = match open_db(ctx) {
        Ok(db) => db,
        Err(response) => return response,
    };
    let rows = db.list_rules().unwrap_or_default();
    let revisions = db.rule_revisions(None, 40).unwrap_or_default();
    let mut geo = crate::geo::update::read_status(&db);
    {
        let data = ctx.geo.read().unwrap_or_else(|poison| poison.into_inner());
        if !data.is_empty() && (geo.country.is_none() || geo.asn.is_none()) {
            geo = crate::geo::update::status_from_data(&data, &geo);
        }
    }
    let notice = request
        .param("notice")
        .and_then(notice_text)
        .map(str::to_string);
    Response::html(pages::rules(
        &page(ctx, view),
        &rows,
        &revisions,
        &geo,
        notice.as_deref(),
        None,
    ))
}

fn page_rule_new(ctx: &Ctx, view: &SessionView) -> Response {
    Response::html(pages::rule_form(
        &page(ctx, view),
        &RuleForm::default(),
        None,
    ))
}

fn page_rule_edit(ctx: &Ctx, view: &SessionView, request: &Request) -> Response {
    let Some(id) = request
        .param("id")
        .and_then(|value| value.parse::<u32>().ok())
    else {
        return Response::error(400, "Invalid rule", "The rule ID is missing or invalid.");
    };
    let db = match open_db(ctx) {
        Ok(db) => db,
        Err(response) => return response,
    };
    match db.get_rule(id) {
        Ok(Some(rule)) => {
            let form = RuleForm::from_rule(&rule);
            Response::html(pages::rule_form(&page(ctx, view), &form, None))
        }
        Ok(None) => Response::error(404, "Rule not found", "That rule no longer exists."),
        Err(e) => Response::error(500, "Rule unavailable", &e.to_string()),
    }
}

fn do_rule_save(ctx: &Ctx, view: &SessionView, request: &Request) -> Response {
    let form = rule_form_from_request(request);
    let note: String = request
        .param("note")
        .unwrap_or("")
        .trim()
        .chars()
        .take(500)
        .collect();
    let rule = match form.to_rule() {
        Ok(rule) => rule,
        Err(error) => {
            return Response::html(pages::rule_form(&page(ctx, view), &form, Some(&error)));
        }
    };
    if let Err(errors) = RuleSet::compile(vec![rule.clone()], &ctx.cfg.ladder.steps) {
        let detail = errors
            .iter()
            .map(|error| error.to_string())
            .collect::<Vec<_>>()
            .join("; ");
        return Response::html(pages::rule_form(&page(ctx, view), &form, Some(&detail)));
    }
    let db = match open_db(ctx) {
        Ok(db) => db,
        Err(response) => return response,
    };
    let by = format!("admin:{}", view.user);
    match db.save_rule(&rule, &by, &note) {
        Ok(stored) => {
            audit(
                ctx,
                &ModelActor::Admin(view.user.clone()),
                "rules.save",
                &stored.id.to_string(),
                &format!("{} ({}); note: {note}", stored.name, stored.action_label()),
            );
            Response::redirect("/rules?notice=rule_saved")
        }
        Err(e) => Response::html(pages::rule_form(
            &page(ctx, view),
            &form,
            Some(&e.to_string()),
        )),
    }
}

fn do_rule_toggle(ctx: &Ctx, view: &SessionView, request: &Request) -> Response {
    let Some(id) = request
        .param("id")
        .and_then(|value| value.parse::<u32>().ok())
    else {
        return Response::redirect("/rules?notice=rule_missing");
    };
    let enable = request.param("enable") == Some("yes");
    let db = match open_db(ctx) {
        Ok(db) => db,
        Err(response) => return response,
    };
    let mut rule = match db.get_rule(id) {
        Ok(Some(rule)) => rule,
        Ok(None) => return Response::redirect("/rules?notice=rule_missing"),
        Err(e) => return Response::error(500, "Rule unchanged", &e.to_string()),
    };
    rule.enabled = enable;
    match db.save_rule(
        &rule,
        &format!("admin:{}", view.user),
        if enable {
            "enabled from rule list"
        } else {
            "disabled from rule list"
        },
    ) {
        Ok(stored) => {
            audit(
                ctx,
                &ModelActor::Admin(view.user.clone()),
                if enable {
                    "rules.enable"
                } else {
                    "rules.disable"
                },
                &stored.id.to_string(),
                &stored.name,
            );
            Response::redirect(if enable {
                "/rules?notice=rule_enabled"
            } else {
                "/rules?notice=rule_disabled"
            })
        }
        Err(crate::error::Error::Invalid(message)) if message.contains("last enabled") => {
            Response::redirect("/rules?notice=rule_last_enabled")
        }
        Err(e) => Response::error(400, "Rule unchanged", &e.to_string()),
    }
}

fn do_rule_delete(ctx: &Ctx, view: &SessionView, request: &Request) -> Response {
    let Some(id) = request
        .param("id")
        .and_then(|value| value.parse::<u32>().ok())
    else {
        return Response::redirect("/rules?notice=rule_missing");
    };
    let db = match open_db(ctx) {
        Ok(db) => db,
        Err(response) => return response,
    };
    match db.delete_rule(id, &format!("admin:{}", view.user)) {
        Ok(true) => {
            audit(
                ctx,
                &ModelActor::Admin(view.user.clone()),
                "rules.delete",
                &id.to_string(),
                "rule deleted",
            );
            Response::redirect("/rules?notice=rule_deleted")
        }
        Ok(false) => Response::redirect("/rules?notice=rule_missing"),
        Err(e) => Response::error(400, "Rule unchanged", &e.to_string()),
    }
}

fn do_rule_import(ctx: &Ctx, view: &SessionView, request: &Request) -> Response {
    let document = request.param("document").unwrap_or("").trim();
    if document.is_empty() {
        return Response::error(400, "No document", "Paste a rules document to import.");
    }
    let value: serde_json::Value = match serde_json::from_str(document) {
        Ok(value) => value,
        Err(e) => {
            return Response::error(
                400,
                "Invalid JSON",
                &format!("The document is not valid JSON: {e}"),
            );
        }
    };
    let candidate = if value.is_array() {
        value
    } else if let Some(rules) = value.get("rules") {
        rules.clone()
    } else {
        return Response::error(
            400,
            "No rules found",
            "Use a bare JSON array or a document with a `rules` array.",
        );
    };
    let rules: Vec<crate::rules::Rule> = match serde_json::from_value(candidate) {
        Ok(rules) => rules,
        Err(e) => {
            return Response::error(
                400,
                "Invalid rules",
                &format!("The rules could not be decoded: {e}"),
            );
        }
    };
    if let Err(errors) = RuleSet::compile(rules.clone(), &ctx.cfg.ladder.steps) {
        let detail = errors
            .iter()
            .map(|error| error.to_string())
            .collect::<Vec<_>>()
            .join("; ");
        return Response::error(400, "Rules rejected", &detail);
    }
    let db = match open_db(ctx) {
        Ok(db) => db,
        Err(response) => return response,
    };
    match db.replace_rules(&rules, &format!("admin:{}", view.user), "import via UI") {
        Ok(()) => {
            audit(
                ctx,
                &ModelActor::Admin(view.user.clone()),
                "rules.import",
                "",
                &format!("{} rule(s) imported", rules.len()),
            );
            Response::redirect("/rules?notice=rules_imported")
        }
        Err(e) => Response::error(400, "Rules unchanged", &e.to_string()),
    }
}

fn do_load_geo_samples(ctx: &Ctx, view: &SessionView) -> Response {
    let db = match open_db(ctx) {
        Ok(db) => db,
        Err(response) => return response,
    };
    match db.add_rules_if_missing(
        &crate::rules::sample_geo_rules(),
        &format!("admin:{}", view.user),
        "sample geo rule",
    ) {
        Ok(added) => {
            audit(
                ctx,
                &ModelActor::Admin(view.user.clone()),
                "rules.samples",
                "",
                &format!("{added} geo sample rule(s) added disabled"),
            );
            Response::redirect("/rules?notice=geo_samples_loaded")
        }
        Err(e) => Response::error(500, "Samples not loaded", &e.to_string()),
    }
}

fn do_geo_check(ctx: &Ctx, view: &SessionView) -> Response {
    let db = match open_db(ctx) {
        Ok(db) => db,
        Err(response) => return response,
    };
    let request = Utc::now().to_rfc3339();
    if let Err(e) = db.set_setting("geo.request", &serde_json::json!(request)) {
        return Response::error(500, "Geo check not queued", &e.to_string());
    }
    audit(
        ctx,
        &ModelActor::Admin(view.user.clone()),
        "geo.check",
        "",
        "manual geo update requested",
    );
    Response::redirect("/rules?notice=geo_check_requested")
}

fn page_rule_history(ctx: &Ctx, view: &SessionView, request: &Request) -> Response {
    let id = request
        .param("id")
        .and_then(|value| value.parse::<u32>().ok());
    let db = match open_db(ctx) {
        Ok(db) => db,
        Err(response) => return response,
    };
    let revisions = db.rule_revisions(id, 200).unwrap_or_default();
    Response::html(pages::rule_history(&page(ctx, view), id, &revisions))
}

fn page_rule_check(ctx: &Ctx, view: &SessionView) -> Response {
    let db = match open_db(ctx) {
        Ok(db) => db,
        Err(response) => return response,
    };
    let stored = db.list_rules().unwrap_or_default();
    let set = match RuleSet::compile(stored, &ctx.cfg.ladder.steps) {
        Ok(set) => set,
        Err(errors) => {
            let geo = geo_data(ctx);
            return Response::html(pages::rule_check(&page(ctx, view), &[], &errors, &geo));
        }
    };
    let rows = db.recent_detections(100).unwrap_or_default();
    let mut evaluated = Vec::with_capacity(rows.len());
    for detection in rows {
        let history = if detection.has_source() {
            History {
                strikes: db.strike_count(detection.src).unwrap_or(0),
                blocked: db.active_block(detection.src).ok().flatten().is_some(),
                last_strike_seen: db.strike_last_seen(detection.src).unwrap_or(None),
            }
        } else {
            History::default()
        };
        let geo_info = {
            let data = ctx.geo.read().unwrap_or_else(|poison| poison.into_inner());
            data.lookup(detection.src)
        };
        let decision = set.evaluate(&detection, &history, &geo_info);
        evaluated.push((detection, decision));
    }
    let geo = geo_data(ctx);
    Response::html(pages::rule_check(&page(ctx, view), &evaluated, &[], &geo))
}

fn rules_export(ctx: &Ctx) -> Response {
    let db = match open_db(ctx) {
        Ok(db) => db,
        Err(response) => return response,
    };
    let rules = db.list_rules().unwrap_or_default();
    Response::json(serde_json::json!({
        "format": "rustips-rules",
        "version": 1,
        "exported_at": Utc::now(),
        "rules": rules,
    }))
}

// ---------------------------------------------------------------------- alerts

fn page_alerts(ctx: &Ctx, view: &SessionView, request: &Request) -> Response {
    let db = match open_db(ctx) {
        Ok(db) => db,
        Err(response) => return response,
    };
    let stats = db.alert_stats().unwrap_or_default();
    let rows = db.list_alerts(200).unwrap_or_default();
    let targets = db.list_alert_targets().unwrap_or_default();
    let retention_days = db
        .get_setting("alerts.retention_days")
        .ok()
        .flatten()
        .and_then(|value| value.as_u64())
        .unwrap_or(ctx.cfg.alerts.retention_days);
    let notice = request
        .param("notice")
        .and_then(notice_text)
        .map(str::to_string);
    let geo = geo_data(ctx);
    Response::html(pages::alerts(
        &page(ctx, view),
        &targets,
        retention_days,
        &stats,
        &rows,
        notice.as_deref(),
        &geo,
    ))
}

fn page_alert_target_new(ctx: &Ctx, view: &SessionView) -> Response {
    let now = Utc::now();
    let target = crate::db::AlertTarget {
        id: 0,
        name: String::new(),
        enabled: true,
        url: String::new(),
        events: "all".into(),
        min_severity: "warning".into(),
        timeout_secs: 5,
        max_retries: 5,
        rate_limit_secs: 60,
        queue_max: 1000,
        created_at: now,
        updated_at: now,
        updated_by: String::new(),
    };
    Response::html(pages::alert_target_form(&page(ctx, view), &target, None))
}

fn page_alert_target_edit(ctx: &Ctx, view: &SessionView, request: &Request) -> Response {
    let Some(id) = request
        .param("id")
        .and_then(|value| value.parse::<i64>().ok())
    else {
        return Response::redirect("/alerts?notice=alert_target_missing");
    };
    let db = match open_db(ctx) {
        Ok(db) => db,
        Err(response) => return response,
    };
    match db.get_alert_target(id) {
        Ok(Some(target)) => {
            Response::html(pages::alert_target_form(&page(ctx, view), &target, None))
        }
        Ok(None) => Response::redirect("/alerts?notice=alert_target_missing"),
        Err(e) => Response::error(500, "Target unavailable", &e.to_string()),
    }
}

fn alert_target_from_request(
    request: &Request,
    now: chrono::DateTime<Utc>,
    by: &str,
) -> std::result::Result<crate::db::AlertTarget, String> {
    let text = |name: &str| request.param(name).unwrap_or("").trim().to_string();
    let name = text("name");
    if name.is_empty() || name.chars().count() > 120 {
        return Err("name is required and must be at most 120 characters".into());
    }
    let url = text("url");
    if url.is_empty()
        || url.chars().any(|c| c.is_whitespace() || c.is_control())
        || !(url.starts_with("https://") || url.starts_with("http://"))
    {
        return Err("URL must be an http(s) URL without whitespace".into());
    }
    let events = text("events");
    if !matches!(events.as_str(), "all" | "detection" | "operational") {
        return Err("events must be all, detection or operational".into());
    }
    let min_severity = text("min_severity");
    if !matches!(min_severity.as_str(), "info" | "warning" | "critical") {
        return Err("minimum severity must be info, warning or critical".into());
    }
    let number = |name: &str, min: u64, max: u64| -> std::result::Result<u64, String> {
        let value: u64 = text(name)
            .parse()
            .map_err(|_| format!("{name} must be a number"))?;
        if value < min || value > max {
            return Err(format!("{name} must be {min}..={max}"));
        }
        Ok(value)
    };
    Ok(crate::db::AlertTarget {
        id: text("id").parse().unwrap_or(0),
        name,
        enabled: request.param("enabled").is_some(),
        url,
        events,
        min_severity,
        timeout_secs: number("timeout_secs", 1, 60)?,
        max_retries: number("max_retries", 0, 20)? as u32,
        rate_limit_secs: number("rate_limit_secs", 1, 86_400)?,
        queue_max: number("queue_max", 1, 1_000_000)? as usize,
        created_at: now,
        updated_at: now,
        updated_by: by.to_string(),
    })
}

fn do_alert_target_save(ctx: &Ctx, view: &SessionView, request: &Request) -> Response {
    let by = format!("admin:{}", view.user);
    let target = match alert_target_from_request(request, Utc::now(), &by) {
        Ok(target) => target,
        Err(error) => {
            let now = Utc::now();
            let draft = crate::db::AlertTarget {
                id: request
                    .param("id")
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(0),
                name: request.param("name").unwrap_or("").to_string(),
                enabled: request.param("enabled").is_some(),
                url: request.param("url").unwrap_or("").to_string(),
                events: request.param("events").unwrap_or("all").to_string(),
                min_severity: request
                    .param("min_severity")
                    .unwrap_or("warning")
                    .to_string(),
                timeout_secs: request
                    .param("timeout_secs")
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(5),
                max_retries: request
                    .param("max_retries")
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(5),
                rate_limit_secs: request
                    .param("rate_limit_secs")
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(60),
                queue_max: request
                    .param("queue_max")
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(1000),
                created_at: now,
                updated_at: now,
                updated_by: by,
            };
            return Response::html(pages::alert_target_form(
                &page(ctx, view),
                &draft,
                Some(&error),
            ));
        }
    };
    let db = match open_db(ctx) {
        Ok(db) => db,
        Err(response) => return response,
    };
    match db.save_alert_target(&target, &format!("admin:{}", view.user)) {
        Ok(stored) => {
            audit(
                ctx,
                &ModelActor::Admin(view.user.clone()),
                "alert.target.save",
                &stored.id.to_string(),
                &format!("{} -> {}", stored.name, stored.url),
            );
            Response::redirect("/alerts?notice=alert_target_saved")
        }
        Err(e) => Response::html(pages::alert_target_form(
            &page(ctx, view),
            &target,
            Some(&e.to_string()),
        )),
    }
}

fn do_alert_target_delete(ctx: &Ctx, view: &SessionView, request: &Request) -> Response {
    let Some(id) = request
        .param("id")
        .and_then(|value| value.parse::<i64>().ok())
    else {
        return Response::redirect("/alerts?notice=alert_target_missing");
    };
    let db = match open_db(ctx) {
        Ok(db) => db,
        Err(response) => return response,
    };
    match db.delete_alert_target(id) {
        Ok(true) => {
            audit(
                ctx,
                &ModelActor::Admin(view.user.clone()),
                "alert.target.delete",
                &id.to_string(),
                "pending alerts for the target were dropped",
            );
            Response::redirect("/alerts?notice=alert_target_deleted")
        }
        Ok(false) => Response::redirect("/alerts?notice=alert_target_missing"),
        Err(e) => Response::error(500, "Target unchanged", &e.to_string()),
    }
}

fn do_alert_settings(ctx: &Ctx, view: &SessionView, request: &Request) -> Response {
    let days = request
        .param("retention_days")
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| (1..=3650).contains(value));
    let Some(days) = days else {
        return Response::redirect("/alerts?notice=alert_settings_invalid");
    };
    let db = match open_db(ctx) {
        Ok(db) => db,
        Err(response) => return response,
    };
    if let Err(e) = db.set_setting("alerts.retention_days", &serde_json::json!(days)) {
        return Response::error(500, "Alert settings unchanged", &e.to_string());
    }
    audit(
        ctx,
        &ModelActor::Admin(view.user.clone()),
        "alert.settings",
        "retention_days",
        &days.to_string(),
    );
    Response::redirect("/alerts?notice=alert_settings_saved")
}

fn do_alert_requeue(ctx: &Ctx, view: &SessionView, request: &Request) -> Response {
    let Some(id) = request
        .param("id")
        .and_then(|value| value.parse::<i64>().ok())
    else {
        return Response::redirect("/alerts?notice=alert_missing");
    };
    let db = match open_db(ctx) {
        Ok(db) => db,
        Err(response) => return response,
    };
    match db.requeue_alert(id, Utc::now()) {
        Ok(true) => {
            audit(
                ctx,
                &ModelActor::Admin(view.user.clone()),
                "alert.requeue",
                &id.to_string(),
                "delivery requested",
            );
            Response::redirect("/alerts?notice=alert_requeued")
        }
        Ok(false) => Response::redirect("/alerts?notice=alert_missing"),
        Err(e) => Response::error(500, "Alert unchanged", &e.to_string()),
    }
}

fn do_alert_delete(ctx: &Ctx, view: &SessionView, request: &Request) -> Response {
    let Some(id) = request
        .param("id")
        .and_then(|value| value.parse::<i64>().ok())
    else {
        return Response::redirect("/alerts?notice=alert_missing");
    };
    let db = match open_db(ctx) {
        Ok(db) => db,
        Err(response) => return response,
    };
    match db.delete_alert(id) {
        Ok(true) => {
            audit(
                ctx,
                &ModelActor::Admin(view.user.clone()),
                "alert.delete",
                &id.to_string(),
                "queue row deleted",
            );
            Response::redirect("/alerts?notice=alert_deleted")
        }
        Ok(false) => Response::redirect("/alerts?notice=alert_missing"),
        Err(e) => Response::error(500, "Alert unchanged", &e.to_string()),
    }
}

fn do_alert_clear(ctx: &Ctx, view: &SessionView) -> Response {
    let db = match open_db(ctx) {
        Ok(db) => db,
        Err(response) => return response,
    };
    match db.clear_finished_alerts() {
        Ok(count) => {
            audit(
                ctx,
                &ModelActor::Admin(view.user.clone()),
                "alert.clear",
                "",
                &format!("{count} finished alert(s) removed"),
            );
            Response::redirect("/alerts?notice=alerts_cleared")
        }
        Err(e) => Response::error(500, "Alerts unchanged", &e.to_string()),
    }
}

fn do_alert_test(ctx: &Ctx, view: &SessionView) -> Response {
    let db = match open_db(ctx) {
        Ok(db) => db,
        Err(response) => return response,
    };
    match crate::alerts::enqueue_test(&db, Utc::now()) {
        Ok(0) => Response::redirect("/alerts?notice=alerts_no_targets"),
        Ok(_) => {
            audit(
                ctx,
                &ModelActor::Admin(view.user.clone()),
                "alert.test",
                "",
                "test alert queued",
            );
            Response::redirect("/alerts?notice=alert_test_queued")
        }
        Err(e) => Response::error(500, "Test alert not queued", &e.to_string()),
    }
}

// ---------------------------------------------------------------------- blocks

fn page_blocks(_ctx: &Ctx, _view: &SessionView, _request: &Request) -> Response {
    // Active blocks now live in the Firewall's Active Drops tab.
    Response::redirect("/firewall?tab=active")
}

fn partial_blocks(ctx: &Ctx, view: &SessionView) -> Response {
    let db = match open_db(ctx) {
        Ok(db) => db,
        Err(response) => return response,
    };
    // The Active Drops tab only shows expiring blocks. Permanent blocks have
    // their own tab and must not leak into the live refresh fragment.
    let rows: Vec<crate::model::Block> = db
        .list_active_blocks()
        .unwrap_or_default()
        .into_iter()
        .filter(|block| !block.is_permanent())
        .collect();
    let geo = geo_data(ctx);
    Response::html(pages::block_rows(
        &page(ctx, view),
        &rows,
        Utc::now(),
        &geo,
        "active",
    ))
}

fn page_history(ctx: &Ctx, view: &SessionView) -> Response {
    let db = match open_db(ctx) {
        Ok(db) => db,
        Err(response) => return response,
    };
    let rows = db.list_block_history(500).unwrap_or_default();
    let geo = geo_data(ctx);
    Response::html(pages::history(&page(ctx, view), &rows, &geo))
}

fn page_strikes(ctx: &Ctx, view: &SessionView) -> Response {
    let db = match open_db(ctx) {
        Ok(db) => db,
        Err(response) => return response,
    };
    let rows = db.list_strikes().unwrap_or_default();
    let geo = geo_data(ctx);
    Response::html(pages::strikes(&page(ctx, view), &rows, &ctx.cfg, &geo))
}

// ------------------------------------------------------------------- allowlist

fn page_allowlist(ctx: &Ctx, view: &SessionView, request: &Request) -> Response {
    let db = match open_db(ctx) {
        Ok(db) => db,
        Err(response) => return response,
    };
    let rows = db.list_allowlist().unwrap_or_default();
    let notice = request
        .param("notice")
        .and_then(notice_text)
        .map(str::to_string);
    Response::html(pages::allowlist(&page(ctx, view), &rows, notice.as_deref()))
}

fn do_allow_add(ctx: &Ctx, view: &SessionView, request: &Request) -> Response {
    let raw = request.param("cidr").unwrap_or("").trim();
    let cidr = match Cidr::parse(raw) {
        Ok(cidr) => cidr,
        Err(e) => {
            tracing::info!("rejected allowlist entry: {e}");
            return Response::redirect("/allowlist?notice=invalid_cidr");
        }
    };
    let label = sanitize_label(request.param("label").unwrap_or(""));
    let db = match open_db(ctx) {
        Ok(db) => db,
        Err(response) => return response,
    };
    match db.add_allowlist(&cidr, &label, false, &format!("admin:{}", view.user)) {
        Ok(()) => {
            audit(
                ctx,
                &ModelActor::Admin(view.user.clone()),
                "allowlist.add",
                &cidr.to_string(),
                &label,
            );
            Response::redirect("/allowlist?notice=allowlist_added")
        }
        Err(e) => {
            let text = e.to_string();
            if text.contains("UNIQUE") || text.contains("constraint") {
                Response::redirect("/allowlist?notice=allowlist_duplicate")
            } else {
                tracing::warn!("allowlist insert failed: {e}");
                Response::error(500, "Allowlist unchanged", "The entry could not be stored.")
            }
        }
    }
}

fn do_allow_remove(ctx: &Ctx, view: &SessionView, request: &Request) -> Response {
    let cidr = request.param("cidr").unwrap_or("").trim();
    if cidr.is_empty() {
        return Response::redirect("/allowlist?notice=invalid_cidr");
    }
    let db = match open_db(ctx) {
        Ok(db) => db,
        Err(response) => return response,
    };
    match db.remove_allowlist(cidr) {
        Ok(true) => {
            audit(
                ctx,
                &ModelActor::Admin(view.user.clone()),
                "allowlist.remove",
                cidr,
                "",
            );
            Response::redirect("/allowlist?notice=allowlist_removed")
        }
        Ok(false) => Response::redirect("/allowlist?notice=allowlist_missing"),
        Err(_) => Response::redirect("/allowlist?notice=allowlist_implicit"),
    }
}

// -------------------------------------------------------------------- settings

fn page_settings(ctx: &Ctx, view: &SessionView, request: &Request) -> Response {
    let db = match open_db(ctx) {
        Ok(db) => db,
        Err(response) => return response,
    };
    let overrides = db.list_settings().unwrap_or_default();
    let country_colors = countries::load(&db);
    let country_default = countries::load_default(&db);
    let country_loaded = geo_data(ctx).country.is_some();
    let edit_code = request
        .param("edit")
        .and_then(countries::normalize_code)
        .unwrap_or_default();
    let edit_color = country_colors.get(&edit_code);
    let edit_background = edit_color
        .map(|color| color.background.clone())
        .unwrap_or_else(|| country_default.background.clone());
    let edit_foreground = edit_color
        .map(|color| color.foreground.clone())
        .unwrap_or_else(|| country_default.foreground.clone());
    let users = auth::users_in_group(&ctx.cfg.web.admin_group);
    let notice = request
        .param("notice")
        .and_then(notice_text)
        .map(str::to_string);

    let mut bind_value = ctx.cfg.web.bind.clone();
    let mut port_value = ctx.cfg.web.port;
    for (key, value) in &overrides {
        match (key.as_str(), value) {
            ("web.bind", serde_json::Value::String(text)) if !text.is_empty() => {
                bind_value = text.clone();
            }
            ("web.port", serde_json::Value::Number(number)) => {
                if let Some(port) = number.as_u64() {
                    port_value = port as u16;
                }
            }
            _ => {}
        }
    }

    let alert_stats = db.alert_stats().unwrap_or_default();
    let alert_targets = db.list_alert_targets().unwrap_or_default().len();
    Response::html(pages::settings(
        &page(ctx, view),
        &ctx.cfg,
        &overrides,
        &country_colors,
        &country_default,
        country_loaded,
        &edit_code,
        &edit_background,
        &edit_foreground,
        &users,
        &bind_value,
        port_value,
        &alert_stats,
        alert_targets,
        notice.as_deref(),
    ))
}

fn do_settings(ctx: &Ctx, view: &SessionView, request: &Request) -> Response {
    let bind_raw = request.param("bind").unwrap_or("").trim();
    let ip = match bind_raw.parse::<IpAddr>() {
        Ok(ip) => net::normalise(ip),
        Err(_) => return Response::redirect("/settings?notice=invalid_ip"),
    };
    let port = match request.param("port").unwrap_or("").trim().parse::<u16>() {
        Ok(port) if port > 0 => port,
        _ => return Response::redirect("/settings?notice=invalid_port"),
    };
    if !ip.is_loopback() && request.param("confirm_remote") != Some("yes") {
        return Response::redirect("/settings?notice=need_confirm");
    }

    let wanted = SocketAddr::new(ip, port);
    if wanted != ctx.bind {
        let _guard = ctx.settings_lock.lock().unwrap_or_else(|e| e.into_inner());
        match TcpListener::bind(wanted) {
            Ok(probe) => drop(probe),
            Err(e) => {
                tracing::warn!(addr = %wanted, error = %e, "settings bind test failed");
                return Response::redirect("/settings?notice=bind_failed");
            }
        }
    }

    let db = match open_db(ctx) {
        Ok(db) => db,
        Err(response) => return response,
    };
    if let Err(e) = db
        .set_setting("web.bind", &serde_json::json!(bind_raw))
        .and_then(|()| db.set_setting("web.port", &serde_json::json!(port)))
    {
        tracing::warn!("settings write failed: {e}");
        return Response::error(
            500,
            "Settings unchanged",
            "The new binding could not be saved.",
        );
    }
    audit(
        ctx,
        &ModelActor::Admin(view.user.clone()),
        "settings.web",
        &wanted.to_string(),
        "saved; applies after restart",
    );
    tracing::warn!(
        actor = %view.user,
        addr = %wanted,
        "web bind/port changed in the UI; restart RustIPS to apply"
    );
    Response::redirect("/settings?notice=saved")
}

fn do_settings_reset(ctx: &Ctx, view: &SessionView) -> Response {
    let db = match open_db(ctx) {
        Ok(db) => db,
        Err(response) => return response,
    };
    if let Err(e) = db
        .delete_setting("web.bind")
        .and_then(|()| db.delete_setting("web.port"))
    {
        tracing::warn!("settings reset failed: {e}");
        return Response::error(
            500,
            "Settings unchanged",
            "The override could not be removed.",
        );
    }
    audit(
        ctx,
        &ModelActor::Admin(view.user.clone()),
        "settings.web.reset",
        &ctx.bind.to_string(),
        "web bind/port override removed",
    );
    Response::redirect("/settings?notice=reset")
}

fn do_country_color_save(ctx: &Ctx, view: &SessionView, request: &Request) -> Response {
    let Some(codes) = request.param("code").and_then(countries::normalize_codes) else {
        return Response::redirect("/settings?notice=country_color_invalid");
    };
    let Some(background) = request
        .param("background")
        .and_then(countries::normalize_color)
    else {
        return Response::redirect("/settings?notice=country_color_invalid");
    };
    let Some(foreground) = request
        .param("foreground")
        .and_then(countries::normalize_color)
    else {
        return Response::redirect("/settings?notice=country_color_invalid");
    };
    let db = match open_db(ctx) {
        Ok(db) => db,
        Err(response) => return response,
    };
    let mut colors = countries::load(&db);
    for code in &codes {
        colors.insert(
            code.clone(),
            countries::CountryColor {
                background: background.clone(),
                foreground: foreground.clone(),
            },
        );
    }
    if let Err(e) = countries::save(&db, &colors) {
        return Response::error(500, "Color unchanged", &e.to_string());
    }
    audit(
        ctx,
        &ModelActor::Admin(view.user.clone()),
        "settings.geo_colors",
        &codes.join(","),
        &format!("background={background} foreground={foreground}"),
    );
    Response::redirect("/settings?notice=country_color_saved")
}

fn do_country_default_save(ctx: &Ctx, view: &SessionView, request: &Request) -> Response {
    let Some(background) = request
        .param("background")
        .and_then(countries::normalize_color)
    else {
        return Response::redirect("/settings?notice=country_color_invalid");
    };
    let Some(foreground) = request
        .param("foreground")
        .and_then(countries::normalize_color)
    else {
        return Response::redirect("/settings?notice=country_color_invalid");
    };
    let db = match open_db(ctx) {
        Ok(db) => db,
        Err(response) => return response,
    };
    if let Err(e) = countries::save_default(
        &db,
        &countries::CountryColor {
            background: background.clone(),
            foreground: foreground.clone(),
        },
    ) {
        return Response::error(500, "Color unchanged", &e.to_string());
    }
    audit(
        ctx,
        &ModelActor::Admin(view.user.clone()),
        "settings.geo_default",
        "default",
        &format!("background={background} foreground={foreground}"),
    );
    Response::redirect("/settings?notice=country_default_saved")
}

fn do_country_color_delete(ctx: &Ctx, view: &SessionView, request: &Request) -> Response {
    let Some(code) = request.param("code").and_then(countries::normalize_code) else {
        return Response::redirect("/settings?notice=country_color_invalid");
    };
    let db = match open_db(ctx) {
        Ok(db) => db,
        Err(response) => return response,
    };
    let mut colors = countries::load(&db);
    colors.remove(&code);
    if let Err(e) = countries::save(&db, &colors) {
        return Response::error(500, "Color unchanged", &e.to_string());
    }
    audit(
        ctx,
        &ModelActor::Admin(view.user.clone()),
        "settings.geo_colors.remove",
        &code,
        "custom country color removed",
    );
    Response::redirect("/settings?notice=country_color_removed")
}

// --------------------------------------------------------------- block actions

fn do_block(ctx: &Ctx, view: &SessionView, request: &Request) -> Response {
    let raw = request.param("src").unwrap_or("").trim();
    let ip = match raw.parse::<IpAddr>() {
        Ok(ip) => net::normalise(ip),
        Err(_) => return Response::redirect("/firewall?tab=active&notice=invalid_ip"),
    };
    if net::is_implicitly_allowed(ip) {
        return Response::redirect("/firewall?tab=active&notice=implicit");
    }
    let duration = match request.param("minutes").unwrap_or("60").trim() {
        "" | "0" | "permanent" | "forever" => BlockDuration::Permanent,
        value => match value.parse::<i64>() {
            Ok(minutes) if (1..=5_256_000).contains(&minutes) => {
                BlockDuration::Temporary(minutes * 60)
            }
            _ => return Response::redirect("/firewall?tab=active&notice=invalid_duration"),
        },
    };
    let permanent = matches!(duration, BlockDuration::Permanent);
    let reason = sanitize_reason(request.param("reason").unwrap_or("manual block"));

    let db = match open_db(ctx) {
        Ok(db) => db,
        Err(response) => return response,
    };
    if let Ok(allow) = db.allowlist_matcher()
        && allow.iter().any(|cidr| cidr.contains(ip))
    {
        return Response::redirect("/firewall?tab=active&notice=allowlisted");
    }
    let strike = db.strike_count(ip).unwrap_or(0);
    let block = match db.upsert_block(ip, duration, strike, &reason, None, None, Utc::now()) {
        Ok((block, _created)) => block,
        Err(e) => {
            tracing::warn!("manual block failed: {e}");
            return Response::error(500, "Block not applied", "The block could not be stored.");
        }
    };

    let mut detail = format!("duration={duration:?} enforced=false");
    if ctx.cfg.mode == Mode::Enforce {
        match ctx.enforcer.add(ip) {
            Ok(()) => {
                let _ = db.set_enforced(block.id, true);
                detail = format!("duration={duration:?} enforced=true");
            }
            Err(e) => {
                tracing::error!(ip = %ip, "manual block could not be enforced: {e}");
                detail = format!("duration={duration:?} enforced=false error={e}");
            }
        }
    }
    audit(
        ctx,
        &ModelActor::Admin(view.user.clone()),
        "block.manual",
        &ip.to_string(),
        &detail,
    );
    tracing::warn!(actor = %view.user, ip = %ip, %duration, "manual block");
    Response::redirect(if permanent {
        "/firewall?tab=permanent&notice=blocked"
    } else {
        "/firewall?tab=active&notice=blocked"
    })
}

fn do_unblock(ctx: &Ctx, view: &SessionView, request: &Request) -> Response {
    let tab = if request.param("tab") == Some("permanent") {
        "permanent"
    } else {
        "active"
    };
    let back = |notice: &str| format!("/firewall?tab={tab}&notice={notice}");
    let raw = request.param("src").unwrap_or("").trim();
    let ip = match raw.parse::<IpAddr>() {
        Ok(ip) => net::normalise(ip),
        Err(_) => return Response::redirect(&back("invalid_ip")),
    };
    let db = match open_db(ctx) {
        Ok(db) => db,
        Err(response) => return response,
    };
    let Some(block) = db.active_block(ip).unwrap_or(None) else {
        return Response::redirect(&back("not_blocked"));
    };
    if ctx.cfg.mode == Mode::Enforce
        && let Err(e) = ctx.enforcer.remove(ip)
    {
        tracing::error!(ip = %ip, "manual unblock could not be enforced: {e}");
        audit(
            ctx,
            &ModelActor::Admin(view.user.clone()),
            "block.manual_unblock.failed",
            &ip.to_string(),
            &format!("kernel removal failed: {e}"),
        );
        return Response::redirect(&back("unblock_failed"));
    }
    let result = db
        .mark_block_state(block.id, BlockState::ManualUnblocked)
        .and_then(|()| {
            if ctx.cfg.ladder.unblock_effect == UnblockEffect::Reset {
                db.reset_strike(ip)
            } else {
                Ok(())
            }
        });
    if let Err(e) = result {
        tracing::warn!("manual unblock could not be recorded: {e}");
        return Response::error(
            500,
            "Unblock incomplete",
            "The block state could not be saved.",
        );
    }
    audit(
        ctx,
        &ModelActor::Admin(view.user.clone()),
        "block.manual_unblock",
        &ip.to_string(),
        "manual unblock from the UI",
    );
    tracing::warn!(actor = %view.user, ip = %ip, "manual unblock");
    Response::redirect(&back("unblocked"))
}

// --------------------------------------------------------------------- audit

fn page_audit(ctx: &Ctx, view: &SessionView) -> Response {
    let db = match open_db(ctx) {
        Ok(db) => db,
        Err(response) => return response,
    };
    let rows = db.recent_audit_full(500).unwrap_or_default();
    Response::html(pages::audit(&page(ctx, view), &rows))
}

// ------------------------------------------------------------------- helpers

fn sanitize_label(value: &str) -> String {
    value
        .chars()
        .filter(|c| !c.is_control())
        .take(120)
        .collect::<String>()
        .trim()
        .to_string()
}

fn sanitize_reason(value: &str) -> String {
    let text: String = value
        .chars()
        .filter(|c| !c.is_control())
        .take(200)
        .collect();
    let text = text.trim();
    if text.is_empty() {
        "manual block".into()
    } else {
        text.to_string()
    }
}

fn notice_text(code: &str) -> Option<&'static str> {
    match code {
        "blocked" => Some("Block recorded."),
        "unblocked" => Some("Block removed."),
        "not_blocked" => Some("That address has no active block."),
        "unblock_failed" => {
            Some("The kernel block could not be removed; the block is still active.")
        }
        "allowlist_added" => Some("Allowlist entry added."),
        "allowlist_removed" => Some("Allowlist entry removed."),
        "allowlist_duplicate" => Some("That CIDR is already in the allowlist."),
        "allowlist_missing" => Some("That CIDR is not in the allowlist."),
        "allowlist_implicit" => Some("Implicit entries cannot be removed."),
        "invalid_cidr" => Some("That is not a valid CIDR or IP address."),
        "invalid_ip" => Some("That is not a valid IP address."),
        "invalid_port" => Some("The port must be 1..=65535."),
        "invalid_duration" => Some("Use 0 for permanent, or 1..=5256000 minutes."),
        "implicit" => Some("That address is implicitly allowed and cannot be blocked."),
        "allowlisted" => Some("That address is on the allowlist; remove it there first."),
        "saved" => Some("Saved. Restart RustIPS to apply the new binding."),
        "reset" => {
            Some("Binding override removed. The configuration file applies after a restart.")
        }
        "country_color_saved" => Some("Country badge color saved."),
        "country_default_saved" => Some("Default country badge color saved."),
        "country_color_removed" => Some("Country badge color removed."),
        "country_color_invalid" => Some("Use a two-letter country code and #rrggbb colors."),
        "bind_failed" => Some("That address and port cannot be bound; nothing was saved."),
        "need_confirm" => Some("Confirm the non-loopback warning before saving."),
        "rule_saved" => Some("Rule saved. The daemon reloads it within a second."),
        "rule_enabled" => Some("Rule enabled. The daemon reloads it within a second."),
        "rule_disabled" => Some("Rule disabled. The daemon reloads it within a second."),
        "rule_last_enabled" => Some("The last enabled rule cannot be disabled."),
        "rule_deleted" => Some("Rule deleted."),
        "rule_missing" => Some("That rule no longer exists."),
        "detector_enabled" => Some("Detector enabled."),
        "detector_disabled" => Some("Detector disabled; existing blocks remain."),
        "detector_missing" => Some("That detector does not exist."),
        "params_saved" => Some("Detection parameters saved. Restart RustIPS to apply them."),
        "params_reset" => {
            Some("Parameter reset to its built-in default. Restart RustIPS to apply.")
        }
        "params_reset_scope" => {
            Some("Detector parameters reset to built-in defaults. Restart RustIPS to apply.")
        }
        "params_reset_all" => {
            Some("All detection parameter overrides cleared. Restart RustIPS to apply.")
        }
        "honeypot_saved" => Some("Honeypot settings saved. Restart RustIPS to apply them."),
        "honeypot_reset" => Some("Honeypot setting reset. Restart RustIPS to apply."),
        "firewall_enabled" => Some(
            "Service firewall enabled. Allow rules apply within a second; DET-27 records drops.",
        ),
        "firewall_disabled" => {
            Some("Service firewall disabled. Blocked-source rules remain in force.")
        }
        "firewall_saved" => Some("Firewall settings saved and apply within a second."),
        "admin_rule_saved" => Some("Admin drop rule saved."),
        "admin_rule_deleted" => Some("Admin drop rule deleted."),
        "admin_rule_enabled" => Some("Admin drop rule enabled."),
        "admin_rule_disabled" => Some("Admin drop rule disabled."),
        "admin_rule_missing" => Some("That admin drop rule no longer exists."),
        "service_dropped" => Some("Service is now dropped by the firewall."),
        "service_allowed" => Some("Service is allowed again."),
        "service_missing" => Some("That service is no longer discovered."),
        "services_acknowledged" => Some("New services marked as seen."),
        "honeypot_port_saved" => Some(
            "Honeypot ports saved. The firewall allow set updates live; restart RustIPS for DET-26 to watch new ports.",
        ),
        "honeypot_port_invalid" => Some("Honeypot port must be 1..=65535."),
        "honeypot_port_duplicate" => Some("That honeypot port is already configured."),
        "honeypot_port_missing" => Some("That honeypot port is not configured."),
        "rules_imported" => Some("Rule set imported and validated."),
        "geo_check_requested" => {
            Some("Geo update requested; it runs in the background within a few seconds.")
        }
        "geo_samples_loaded" => {
            Some("Sample geo rules loaded disabled; review and enable as needed.")
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(host: &str) -> Request {
        let mut headers = HashMap::new();
        headers.insert("host".to_string(), host.to_string());
        Request {
            method: "GET".into(),
            path: "/".into(),
            http11: true,
            headers,
            query: HashMap::new(),
            form: HashMap::new(),
            peer: "127.0.0.1:5000".parse().unwrap(),
        }
    }

    #[test]
    fn loopback_rejects_foreign_host_headers() {
        let bind: SocketAddr = "127.0.0.1:10707".parse().unwrap();
        assert!(host_allowed(&request("127.0.0.1:10707"), bind));
        assert!(host_allowed(&request("localhost:10707"), bind));
        assert!(!host_allowed(&request("attacker.example:10707"), bind));
        assert!(!host_allowed(&request("192.0.2.5:10707"), bind));
    }

    #[test]
    fn wildcard_bind_accepts_literal_addresses_only() {
        let bind: SocketAddr = "0.0.0.0:10707".parse().unwrap();
        assert!(host_allowed(&request("192.0.2.5:10707"), bind));
        assert!(host_allowed(&request("localhost"), bind));
        assert!(!host_allowed(&request("attacker.example"), bind));
    }

    #[test]
    fn host_port_stripping_handles_ipv6() {
        assert_eq!(strip_host_port("127.0.0.1:10707"), "127.0.0.1");
        assert_eq!(strip_host_port("[::1]:10707"), "::1");
        assert_eq!(strip_host_port("[::1]"), "::1");
        assert_eq!(strip_host_port("::1"), "::1");
        assert_eq!(strip_host_port("localhost"), "localhost");
    }

    #[test]
    fn form_decoding_is_total() {
        let map = parse_form("a=1&b=two+words&c=%3Cscript%3E&d=%zz&e");
        assert_eq!(map.get("a").map(String::as_str), Some("1"));
        assert_eq!(map.get("b").map(String::as_str), Some("two words"));
        assert_eq!(map.get("c").map(String::as_str), Some("<script>"));
        assert_eq!(map.get("d").map(String::as_str), Some("%zz"));
        assert_eq!(map.get("e").map(String::as_str), Some(""));
    }

    #[test]
    fn cookie_flags_are_strict() {
        let cookie = session_cookie("abc", 60);
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Strict"));
        assert!(cookie.contains("Path=/"));
        assert!(clear_cookie().contains("Max-Age=0"));
    }

    #[test]
    fn notices_are_an_allowlist() {
        assert!(notice_text("blocked").is_some());
        assert!(notice_text("<script>").is_none());
    }

    #[test]
    fn reasons_are_bounded_and_stripped() {
        assert_eq!(sanitize_reason("  hello\nworld  "), "helloworld");
        assert_eq!(sanitize_reason("   "), "manual block");
        assert!(sanitize_reason(&"x".repeat(500)).len() <= 200);
    }
}

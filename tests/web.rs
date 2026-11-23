//! End-to-end web UI test: real TCP, real sessions, real SQLite, no PAM
//! service (break-glass path), CSRF enforcement and a manual block.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use rustips::auth;
use rustips::config::{Config, DEFAULT_CONFIG_TOML};
use rustips::daemon::Stats;
use rustips::db::Db;
use rustips::enforce::DryRunEnforcer;
use rustips::geo::{GeoData, GeoHandle, GeoIndex, GeoKind, build_index};
use rustips::logs::{LogEvent, Origin};
use rustips::model::{Detection, Detector, Proto};
use rustips::paths::Layout;
use rustips::web::{self, WebOptions};

fn test_geo(dir: &Path) -> GeoHandle {
    let v4 = dir.join("web-test-geo-v4.csv");
    let v6 = dir.join("web-test-geo-v6.csv");
    let index = dir.join("web-test-country.bin");
    let mut file = std::fs::File::create(&v4).unwrap();
    writeln!(file, "1.0.1.0,1.0.3.255,CN").unwrap();
    writeln!(file, "203.0.113.0,203.0.113.255,US").unwrap();
    drop(file);
    let mut file = std::fs::File::create(&v6).unwrap();
    writeln!(file, "2001:db8::,2001:db8:ffff:ffff:ffff:ffff:ffff:ffff,GB").unwrap();
    drop(file);
    build_index(GeoKind::Country, &v4, &v6, &index).unwrap();
    let index = GeoIndex::open(&index, GeoKind::Country).unwrap();
    Arc::new(RwLock::new(GeoData {
        country: Some(Arc::new(index)),
        asn: None,
    }))
}

struct Response {
    status: u16,
    headers: String,
    body: String,
}

fn http(port: u16, request: &str) -> Response {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream.write_all(request.as_bytes()).unwrap();
    stream.flush().unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).unwrap();
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let status = status_line
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    Response {
        status,
        headers: head.to_string(),
        body: body.to_string(),
    }
}

fn get(port: u16, path: &str, cookie: Option<&str>) -> Response {
    let cookie = cookie
        .map(|c| format!("Cookie: {c}\r\n"))
        .unwrap_or_default();
    http(
        port,
        &format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n{cookie}\r\n"),
    )
}

fn post(port: u16, path: &str, body: &str, cookie: Option<&str>) -> Response {
    let cookie = cookie
        .map(|c| format!("Cookie: {c}\r\n"))
        .unwrap_or_default();
    http(
        port,
        &format!(
            "POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\
             Content-Type: application/x-www-form-urlencoded\r\n\
             Content-Length: {}\r\n{cookie}\r\n{body}",
            body.len()
        ),
    )
}

fn session_cookie(response: &Response) -> String {
    for line in response.headers.split("\r\n") {
        if let Some(value) = line.strip_prefix("Set-Cookie: ") {
            return value.split(';').next().unwrap_or("").to_string();
        }
    }
    panic!("no Set-Cookie in {}", response.headers);
}

fn csrf(response: &Response) -> String {
    let marker = "name=\"csrf\" value=\"";
    let start = response.body.find(marker).expect("csrf field") + marker.len();
    let end = response.body[start..].find('"').unwrap() + start;
    response.body[start..end].to_string()
}

fn url_encode(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            b' ' => out.push('+'),
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

#[test]
fn ui_login_breakglass_and_manual_block() {
    // -------- throwaway state
    let dir = std::env::temp_dir().join(format!(
        "rustips-web-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let layout = Layout {
        config: dir.join("config.toml"),
        state_dir: dir.clone(),
        db: dir.join("rustips.db"),
        backups: dir.join("backups"),
    };
    let db = Db::open(&layout.db).unwrap();
    db.seed_implicit_allowlist().unwrap();
    db.insert_system_sample(chrono::Utc::now(), 12.5, 42.0, 5.25)
        .unwrap();

    // A log-derived detection with stored evidence, including markup that
    // must be escaped by the Logs page.
    let event = LogEvent {
        ts: chrono::Utc::now(),
        origin: Origin::Journal,
        source: "journal".into(),
        unit: Some("ssh.service".into()),
        identifier: Some("sshd-session".into()),
        priority: Some(6),
        host: Some("host".into()),
        pid: Some(1),
        user: Some("bob".into()),
        service: None,
        src_ip: Some("203.0.113.7".parse().unwrap()),
        action: Some("ssh.auth".into()),
        outcome: Some("failure".into()),
        method: None,
        path: None,
        status: None,
        template: "sshd.invalid_user".into(),
        message: "Invalid user <script>alert(1)</script>".into(),
        cursor: Some("s=web-1".into()),
        parser: "sshd".into(),
        id: None,
    };
    let log_id = db.insert_log_event(&event).unwrap().expect("event stored");
    let det = Detection {
        detector: Detector::SshAuthFailures,
        src: "203.0.113.7".parse().unwrap(),
        dst: None,
        dst_port: None,
        proto: Proto::Log,
        count: 5,
        window_secs: 600,
        first_seen: chrono::Utc::now(),
        last_seen: chrono::Utc::now(),
        metadata: serde_json::json!({"template": "sshd.invalid_user"}),
        evidence_log_id: Some(log_id),
        id: None,
    };
    db.insert_detection(&det).unwrap();

    let mut cfg = Config::parse(std::path::Path::new("test.toml"), DEFAULT_CONFIG_TOML).unwrap();
    cfg.web.port = 0;
    // Exercise the Alerts page and test-queue button without a live worker.
    cfg.alerts.enabled = true;
    cfg.alerts.url = "http://127.0.0.1:9/hook".into();

    // -------- a free port (bind, learn it, release it)
    let probe = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);

    let mut handle = web::start(
        &cfg,
        &layout,
        Arc::new(Stats::new()),
        Arc::new(DryRunEnforcer),
        test_geo(&dir),
        WebOptions {
            bind: Some("127.0.0.1".into()),
            port: Some(port),
        },
    )
    .unwrap();
    assert_eq!(handle.addr.port(), port);

    // -------- public endpoints
    let health = get(port, "/healthz", None);
    assert_eq!(health.status, 200, "{}", health.headers);
    assert!(health.body.contains("\"status\":\"ok\""));
    assert!(health.headers.contains("Content-Security-Policy"));

    let ready = get(port, "/readyz", None);
    assert_eq!(ready.status, 200, "{}", ready.headers);
    assert!(ready.body.contains("\"ready\""));
    assert!(ready.body.contains("\"database\":\"ok\""));

    let css = get(port, "/assets/app.css", None);
    assert_eq!(css.status, 200);
    assert!(css.headers.contains("text/css"));

    let login = get(port, "/login", None);
    assert_eq!(login.status, 200);
    assert!(login.body.contains("system account"));

    // Unauthenticated pages bounce to the login form.
    let root = get(port, "/", None);
    assert_eq!(root.status, 303);
    assert!(root.headers.contains("Location: /login"));

    // Foreign Host headers are refused (DNS rebinding guard).
    let bad_host = http(
        port,
        "GET /healthz HTTP/1.1\r\nHost: attacker.example\r\n\r\n",
    );
    assert_eq!(bad_host.status, 421);

    // -------- PAM is absent here, so a password login fails closed
    let denied = post(
        port,
        "/login",
        "user=definitely-not-a-user&pass=wrong",
        None,
    );
    assert_eq!(denied.status, 401);
    assert!(
        denied.body.contains("PAM authentication is unavailable")
            || denied.body.contains("Invalid credentials"),
        "{}",
        denied.body
    );

    // -------- break-glass login
    let token = auth::create_breakglass(&layout.state_dir, Duration::from_secs(300))
        .unwrap()
        .token;
    let bad_token = post(port, "/login", "user=root&token=nope", None);
    assert_eq!(bad_token.status, 401);

    let success = post(port, "/login", &format!("user=root&token={token}"), None);
    assert_eq!(success.status, 303, "{}", success.headers);
    let cookie = session_cookie(&success);

    let dashboard = get(port, "/", Some(&cookie));
    assert_eq!(dashboard.status, 200);
    assert!(dashboard.body.contains("Dashboard"));
    assert!(dashboard.body.contains("Break-glass session"));
    assert!(dashboard.body.contains("class=\"sidebar\""));
    assert!(dashboard.body.contains("side-nav"));
    assert!(dashboard.body.contains("Monitoring"));
    assert!(dashboard.body.contains("Detection"));
    assert!(dashboard.body.contains("Disposition rules"));
    assert!(dashboard.body.contains("Enforcement"));
    assert!(dashboard.body.contains("System"));
    assert!(dashboard.body.contains("class=\"nav-group\""));
    assert!(
        dashboard
            .body
            .contains("<summary class=\"nav-head\">Monitoring</summary>")
    );
    assert!(!dashboard.body.contains("bound to"));
    assert!(!dashboard.body.contains("<footer>RustIPS"));
    assert!(
        dashboard
            .body
            .contains(&format!("RustIPS: {}", env!("CARGO_PKG_VERSION")))
    );
    assert!(dashboard.body.contains("/assets/theme.js"));
    assert!(dashboard.body.contains("id=\"ip-dialog\""));
    assert!(dashboard.body.contains("data-ip=\"203.0.113.7\""));
    assert!(dashboard.body.contains("country-US"));
    assert!(dashboard.body.contains("RustIPS resources"));
    assert!(dashboard.body.contains("id=\"system-graphs\""));
    assert!(dashboard.body.contains("12.5%"));
    assert!(dashboard.body.contains("42.0 MB"));
    assert!(dashboard.body.contains("spark-line"));
    let theme = get(port, "/assets/theme.js", None);
    assert_eq!(theme.status, 200);
    assert!(theme.body.contains("rustips-theme"));
    let csrf_token = csrf(&dashboard);

    let ip_history = get(port, "/api/ip?ip=203.0.113.7", Some(&cookie));
    assert_eq!(ip_history.status, 200, "{}", ip_history.headers);
    assert!(ip_history.body.contains("203.0.113.7"));
    assert!(ip_history.body.contains("DET-16"));
    assert!(ip_history.body.contains("sshd.invalid_user"));
    assert!(ip_history.body.contains("Permanently block"));
    assert!(ip_history.body.contains("name=\"minutes\" value=\"0\""));
    assert!(ip_history.body.contains("Country (ISO)"));
    assert!(ip_history.body.contains("country-US"));
    let unauth_history = get(port, "/api/ip?ip=203.0.113.7", None);
    assert_eq!(unauth_history.status, 303);
    assert!(unauth_history.headers.contains("Location: /login"));

    let system = get(port, "/api/system?hours=24", Some(&cookie));
    assert_eq!(system.status, 200, "{}", system.headers);
    assert!(system.body.contains("system-history"));
    assert!(system.body.contains("CPU"));
    assert!(system.body.contains("Database storage"));
    let compact_system = get(port, "/api/system?hours=1&compact=1", Some(&cookie));
    assert_eq!(compact_system.status, 200);
    assert!(compact_system.body.contains("system-grid"));
    assert!(compact_system.body.contains("12.5%"));
    let unauth_system = get(port, "/api/system?hours=24", None);
    assert_eq!(unauth_system.status, 303);

    let detectors = get(port, "/detectors", Some(&cookie));
    assert_eq!(detectors.status, 200);
    assert!(detectors.body.contains("DET-12"));
    assert!(detectors.body.contains("wp-login"));
    assert!(detectors.body.contains("DET-26"));
    assert!(detectors.body.contains("honeypot"));
    let disabled = post(
        port,
        "/detectors/toggle",
        &format!("id=DET-12&enable=no&csrf={csrf_token}"),
        Some(&cookie),
    );
    assert_eq!(disabled.status, 303, "{}", disabled.headers);
    assert!(
        Db::open(&layout.db)
            .unwrap()
            .is_detector_disabled(Detector::HttpBadPath)
            .unwrap()
    );
    let enabled = post(
        port,
        "/detectors/toggle",
        &format!("id=DET-12&enable=yes&csrf={csrf_token}"),
        Some(&cookie),
    );
    assert_eq!(enabled.status, 303);
    assert!(
        !Db::open(&layout.db)
            .unwrap()
            .is_detector_disabled(Detector::HttpBadPath)
            .unwrap()
    );

    // Editable parameters and reset-to-default; internal detectors are gone.
    let params_page = get(port, "/detectors", Some(&cookie));
    assert_eq!(params_page.status, 200);
    assert!(params_page.body.contains("Shared packet parameters"));
    assert!(params_page.body.contains("Shared HTTP parameters"));
    assert!(params_page.body.contains("Shared log parameters"));
    assert!(params_page.body.contains("http_bad_paths"));
    assert!(params_page.body.contains("Reset to default"));
    assert!(params_page.body.contains("state-toggle"));
    assert!(params_page.body.contains(">Enabled</button>"));
    assert!(!params_page.body.contains("DET-22"));
    assert!(!params_page.body.contains("DET-24"));
    assert!(!params_page.body.contains("DET-25"));
    assert!(!params_page.body.contains("Scope"));

    let saved = post(
        port,
        "/detectors/params",
        &format!(
            "scope=DET-12&action=save&p:detection.http_bad_paths=/.env,%20/custom&csrf={csrf_token}"
        ),
        Some(&cookie),
    );
    assert_eq!(saved.status, 303, "{}", saved.headers);
    let overrides = Db::open(&layout.db).unwrap().detection_overrides().unwrap();
    assert_eq!(
        overrides.get("detection.http_bad_paths").unwrap(),
        "/.env, /custom"
    );
    let modified = get(port, "/detectors", Some(&cookie));
    assert!(modified.body.contains("stored override"));
    assert!(modified.body.contains("/.env, /custom"));

    let login_paths = post(
        port,
        "/detectors/params",
        &format!(
            "scope=DET-13&action=save&p:detection.http_login_paths=/login,%20/signin&csrf={csrf_token}"
        ),
        Some(&cookie),
    );
    assert_eq!(login_paths.status, 303);
    assert!(
        Db::open(&layout.db)
            .unwrap()
            .detection_overrides()
            .unwrap()
            .contains_key("detection.http_login_paths")
    );

    let invalid_param = post(
        port,
        "/detectors/params",
        &format!("scope=DET-01&action=save&p:detection.scan_ports=999999&csrf={csrf_token}"),
        Some(&cookie),
    );
    assert_eq!(invalid_param.status, 400, "{}", invalid_param.headers);
    assert!(
        !Db::open(&layout.db)
            .unwrap()
            .detection_overrides()
            .unwrap()
            .contains_key("detection.scan_ports")
    );

    let reset_one = post(
        port,
        "/detectors/params",
        &format!("scope=DET-12&reset_key=detection.http_bad_paths&csrf={csrf_token}"),
        Some(&cookie),
    );
    assert_eq!(reset_one.status, 303);
    assert!(
        !Db::open(&layout.db)
            .unwrap()
            .detection_overrides()
            .unwrap()
            .contains_key("detection.http_bad_paths")
    );

    let saved_again = post(
        port,
        "/detectors/params",
        &format!(
            "scope=DET-12&action=save&p:detection.http_bad_paths=/.env,%20/probe&csrf={csrf_token}"
        ),
        Some(&cookie),
    );
    assert_eq!(saved_again.status, 303);
    let reset_scope = post(
        port,
        "/detectors/params",
        &format!("scope=DET-12&action=reset_scope&csrf={csrf_token}"),
        Some(&cookie),
    );
    assert_eq!(reset_scope.status, 303);
    assert!(
        !Db::open(&layout.db)
            .unwrap()
            .detection_overrides()
            .unwrap()
            .contains_key("detection.http_bad_paths")
    );

    let reset_all = post(
        port,
        "/detectors/params",
        &format!("action=reset_all&csrf={csrf_token}"),
        Some(&cookie),
    );
    assert_eq!(reset_all.status, 303);
    assert!(
        Db::open(&layout.db)
            .unwrap()
            .detection_overrides()
            .unwrap()
            .is_empty()
    );

    // Saving the running/default value makes no override; a change does.
    let unchanged = post(
        port,
        "/detectors/params",
        &format!("scope=DET-01&action=save&p:detection.scan_ports=20&csrf={csrf_token}"),
        Some(&cookie),
    );
    assert_eq!(unchanged.status, 303);
    assert!(
        Db::open(&layout.db)
            .unwrap()
            .detection_overrides()
            .unwrap()
            .is_empty()
    );
    let changed = post(
        port,
        "/detectors/params",
        &format!("scope=DET-01&action=save&p:detection.scan_ports=25&csrf={csrf_token}"),
        Some(&cookie),
    );
    assert_eq!(changed.status, 303);
    assert_eq!(
        Db::open(&layout.db)
            .unwrap()
            .detection_overrides()
            .unwrap()
            .get("detection.scan_ports")
            .map(String::as_str),
        Some("25")
    );
    let reset_numeric = post(
        port,
        "/detectors/params",
        &format!("scope=DET-01&reset_key=detection.scan_ports&csrf={csrf_token}"),
        Some(&cookie),
    );
    assert_eq!(reset_numeric.status, 303);
    assert!(
        Db::open(&layout.db)
            .unwrap()
            .detection_overrides()
            .unwrap()
            .is_empty()
    );

    // Honeypot settings are edited on the Settings page and use the same
    // validated override store.
    let settings = get(port, "/settings", Some(&cookie));
    assert_eq!(settings.status, 200);
    assert!(settings.body.contains("Honeypot"));
    assert!(settings.body.contains("honeypot_ports"));
    assert!(settings.body.contains("p:detection.honeypot_enabled"));
    assert!(settings.body.contains("p:detection.honeypot_hits"));
    let honeypot_invalid = post(
        port,
        "/detectors/params",
        &format!(
            "scope=honeypot&return=settings&action=save\
             &p:detection.honeypot_enabled=true&p:detection.honeypot_ports=&csrf={csrf_token}"
        ),
        Some(&cookie),
    );
    assert_eq!(honeypot_invalid.status, 400, "{}", honeypot_invalid.headers);
    let honeypot_saved = post(
        port,
        "/detectors/params",
        &format!(
            "scope=honeypot&return=settings&action=save\
             &p:detection.honeypot_enabled=true&p:detection.honeypot_ports=2323,9999\
             &p:detection.honeypot_hits=4&csrf={csrf_token}"
        ),
        Some(&cookie),
    );
    assert_eq!(honeypot_saved.status, 303, "{}", honeypot_saved.headers);
    assert!(honeypot_saved.headers.contains("Location: /settings"));
    let overrides = Db::open(&layout.db).unwrap().detection_overrides().unwrap();
    assert_eq!(
        overrides
            .get("detection.honeypot_enabled")
            .map(String::as_str),
        Some("true")
    );
    assert_eq!(
        overrides
            .get("detection.honeypot_ports")
            .map(String::as_str),
        Some("2323, 9999")
    );
    assert_eq!(
        overrides.get("detection.honeypot_hits").map(String::as_str),
        Some("4")
    );
    let honeypot_reset = post(
        port,
        "/detectors/params",
        &format!("scope=honeypot&return=settings&action=reset_scope&csrf={csrf_token}"),
        Some(&cookie),
    );
    assert_eq!(honeypot_reset.status, 303);
    assert!(honeypot_reset.headers.contains("Location: /settings"));
    assert!(
        Db::open(&layout.db)
            .unwrap()
            .detection_overrides()
            .unwrap()
            .is_empty()
    );
    let honeypot_unchanged = post(
        port,
        "/detectors/params",
        &format!(
            "scope=honeypot&return=settings&action=save\
             &p:detection.honeypot_enabled=false&p:detection.honeypot_ports=\
             &p:detection.honeypot_hits=3&csrf={csrf_token}"
        ),
        Some(&cookie),
    );
    assert_eq!(honeypot_unchanged.status, 303);
    assert!(
        Db::open(&layout.db)
            .unwrap()
            .detection_overrides()
            .unwrap()
            .is_empty()
    );

    // Country badge colors: the default tag is the blue .tag style; the
    // generated stylesheet carries custom entries.
    let colors_css = get(port, "/assets/country-colors.css", None);
    assert_eq!(colors_css.status, 200);
    assert!(
        colors_css
            .body
            .contains(".country-tag { background: #000000; color: #ffffff; }")
    );
    assert!(!colors_css.body.contains(".country-US"));
    let color_saved = post(
        port,
        "/settings/geo-colors",
        &format!("code=US&background=%23b91c1c&foreground=%23ffffff&csrf={csrf_token}"),
        Some(&cookie),
    );
    assert_eq!(color_saved.status, 303, "{}", color_saved.headers);
    assert!(color_saved.headers.contains("Location: /settings"));
    let colors_css = get(port, "/assets/country-colors.css", None);
    assert!(
        colors_css
            .body
            .contains(".country-US { background: #b91c1c; color: #ffffff; }")
    );
    let default_saved = post(
        port,
        "/settings/geo-colors/default",
        &format!("background=%23101010&foreground=%23eeeeee&csrf={csrf_token}"),
        Some(&cookie),
    );
    assert_eq!(default_saved.status, 303);
    let colors_css = get(port, "/assets/country-colors.css", None);
    assert!(
        colors_css
            .body
            .contains(".country-tag { background: #101010; color: #eeeeee; }")
    );
    let color_list = post(
        port,
        "/settings/geo-colors",
        &format!("code=CN,%20RU&background=%23b91c1c&foreground=%23ffffff&csrf={csrf_token}"),
        Some(&cookie),
    );
    assert_eq!(color_list.status, 303);
    let colors_css = get(port, "/assets/country-colors.css", None);
    assert!(
        colors_css
            .body
            .contains(".country-CN { background: #b91c1c; color: #ffffff; }")
    );
    assert!(
        colors_css
            .body
            .contains(".country-RU { background: #b91c1c; color: #ffffff; }")
    );
    let settings = get(port, "/settings", Some(&cookie));
    assert!(settings.body.contains("Country badge colors"));
    assert!(settings.body.contains("country-US"));
    assert!(settings.body.contains("country-CN"));
    assert!(
        settings
            .body
            .contains("href=\"/settings?edit=CN#country-colors\"")
    );
    assert!(settings.body.contains("#b91c1c"));
    let edit = get(port, "/settings?edit=CN", Some(&cookie));
    assert!(edit.body.contains("Update country colors"));
    assert!(
        edit.body
            .contains("name=\"code\" maxlength=\"64\" value=\"CN\"")
    );
    let color_invalid = post(
        port,
        "/settings/geo-colors",
        &format!("code=USA&background=red&foreground=%23fff&csrf={csrf_token}"),
        Some(&cookie),
    );
    assert_eq!(color_invalid.status, 303);
    assert!(
        color_invalid
            .headers
            .contains("Location: /settings?notice=country_color_invalid")
    );
    let color_removed = post(
        port,
        "/settings/geo-colors/delete",
        &format!("code=US&csrf={csrf_token}"),
        Some(&cookie),
    );
    assert_eq!(color_removed.status, 303);
    let colors_css = get(port, "/assets/country-colors.css", None);
    assert!(!colors_css.body.contains(".country-US"));

    // A stored value cannot inject markup into the page.
    let detected = get(port, "/detections", Some(&cookie));
    assert_eq!(detected.status, 200);
    assert!(!detected.body.contains("<script>alert"));

    // The Logs page shows the event and its detection, and escapes markup.
    let logs = get(port, "/logs", Some(&cookie));
    assert_eq!(logs.status, 200, "{}", logs.headers);
    assert!(logs.body.contains("Host logs"));
    assert!(logs.body.contains("this process:"));
    assert!(logs.body.contains("sshd.invalid_user"));
    assert!(logs.body.contains("DET-16"));
    assert!(!logs.body.contains("<script>alert(1)</script>"));
    assert!(logs.body.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));

    let filtered = get(port, "/logs?origin=journal&q=sshd", Some(&cookie));
    assert_eq!(filtered.status, 200);
    assert!(filtered.body.contains("sshd.invalid_user"));
    let empty = get(port, "/logs?q=no-such-event-xyz", Some(&cookie));
    assert_eq!(empty.status, 200);

    // Rules pages and a validated save.
    let rules = get(port, "/rules", Some(&cookie));
    assert_eq!(rules.status, 200);
    assert!(rules.body.contains("Disposition rules"));
    assert!(rules.body.contains("Packet detections escalate"));
    assert!(rules.body.contains("class=\"rules-table\""));
    assert!(rules.body.contains("state-toggle"));
    assert!(get(port, "/rules/new", Some(&cookie)).status == 200);
    assert!(get(port, "/rules/check", Some(&cookie)).status == 200);
    let exported = get(port, "/rules/export", Some(&cookie));
    assert_eq!(exported.status, 200);
    assert!(exported.body.contains("\"rules\""));

    let save = post(
        port,
        "/rules/save",
        &format!(
            "id=0&name=Test+rule&priority=50&severity=warning&enabled=yes\
             &detectors=DET-01&action=alert&note=test&csrf={csrf_token}"
        ),
        Some(&cookie),
    );
    assert_eq!(save.status, 303, "{}", save.headers);
    let listed = get(port, "/rules", Some(&cookie));
    assert!(listed.body.contains("Test rule"));

    let rule_id = Db::open(&layout.db)
        .unwrap()
        .list_rules()
        .unwrap()
        .into_iter()
        .find(|rule| rule.enabled)
        .unwrap()
        .id;
    let rule_off = post(
        port,
        "/rules/toggle",
        &format!("id={rule_id}&enable=no&csrf={csrf_token}"),
        Some(&cookie),
    );
    assert_eq!(rule_off.status, 303, "{}", rule_off.headers);
    assert!(
        !Db::open(&layout.db)
            .unwrap()
            .get_rule(rule_id)
            .unwrap()
            .unwrap()
            .enabled
    );
    let rule_on = post(
        port,
        "/rules/toggle",
        &format!("id={rule_id}&enable=yes&csrf={csrf_token}"),
        Some(&cookie),
    );
    assert_eq!(rule_on.status, 303);
    assert!(
        Db::open(&layout.db)
            .unwrap()
            .get_rule(rule_id)
            .unwrap()
            .unwrap()
            .enabled
    );

    let invalid = post(
        port,
        "/rules/save",
        &format!(
            "id=0&name=Bad+rule&priority=50&severity=warning&enabled=yes\
             &detectors=DET-99&action=alert&csrf={csrf_token}"
        ),
        Some(&cookie),
    );
    assert_eq!(invalid.status, 200);
    assert!(invalid.body.contains("DET-99"));

    // Import replaces the set; the last enabled rule cannot be deleted.
    let document = r#"[{"id":9,"name":"Imported rule","description":"","enabled":true,"priority":50,"severity":"warning","dry_run":false,"when":{},"action":{"type":"alert"}}]"#;
    let imported = post(
        port,
        "/rules/import",
        &format!("document={}&csrf={csrf_token}", url_encode(document)),
        Some(&cookie),
    );
    assert_eq!(imported.status, 303, "{}", imported.headers);
    let listed = get(port, "/rules", Some(&cookie));
    assert!(listed.body.contains("Imported rule"));
    let delete_last = post(
        port,
        "/rules/delete",
        &format!("id=9&csrf={csrf_token}"),
        Some(&cookie),
    );
    assert_eq!(delete_last.status, 400);

    // Sample geo rules load disabled and do not replace the set.
    let samples = post(
        port,
        "/rules/samples/geo",
        &format!("csrf={csrf_token}"),
        Some(&cookie),
    );
    assert_eq!(samples.status, 303, "{}", samples.headers);
    let listed = get(port, "/rules", Some(&cookie));
    assert!(listed.body.contains("Geo alert: China"));
    assert!(listed.body.contains("Geo block 24h: high-risk list"));
    assert!(listed.body.contains("Geo allow: partner ASNs"));

    let settings = get(port, "/settings", Some(&cookie));
    assert_eq!(settings.status, 200);
    assert!(settings.body.contains("Webhook alerts"));

    let alerts = get(port, "/alerts", Some(&cookie));
    assert_eq!(alerts.status, 200);
    assert!(alerts.body.contains("Send test alert"));
    assert!(alerts.body.contains("Default webhook"));
    assert_eq!(get(port, "/alerts/target/new", Some(&cookie)).status, 200);

    let added = post(
        port,
        "/alerts/target/save",
        &format!(
            "id=0&name=Second+target&url=https%3A%2F%2Fexample.test%2Fhook&events=all             &min_severity=warning&timeout_secs=3&max_retries=1&rate_limit_secs=30             &queue_max=50&enabled=yes&csrf={csrf_token}"
        ),
        Some(&cookie),
    );
    assert_eq!(added.status, 303, "{}", added.headers);
    let target = Db::open(&layout.db)
        .unwrap()
        .list_alert_targets()
        .unwrap()
        .into_iter()
        .find(|target| target.name == "Second target")
        .expect("added target");
    let edited = post(
        port,
        "/alerts/target/save",
        &format!(
            "id={}&name=Edited+target&url=https%3A%2F%2Fexample.test%2Fhook2&events=detection             &min_severity=critical&timeout_secs=4&max_retries=2&rate_limit_secs=40             &queue_max=60&enabled=yes&csrf={csrf_token}",
            target.id
        ),
        Some(&cookie),
    );
    assert_eq!(edited.status, 303, "{}", edited.headers);
    let listed = get(port, "/alerts", Some(&cookie));
    assert!(listed.body.contains("Edited target"));
    let removed = post(
        port,
        "/alerts/target/delete",
        &format!("id={}&csrf={csrf_token}", target.id),
        Some(&cookie),
    );
    assert_eq!(removed.status, 303);
    assert!(
        !get(port, "/alerts", Some(&cookie))
            .body
            .contains("Edited target")
    );

    let test_alert = post(
        port,
        "/alerts/test",
        &format!("csrf={csrf_token}"),
        Some(&cookie),
    );
    assert_eq!(test_alert.status, 303, "{}", test_alert.headers);
    let alerts = get(port, "/alerts", Some(&cookie));
    assert!(alerts.body.contains("RustIPS webhook test"));

    let summary = get(port, "/api/summary", Some(&cookie));
    assert_eq!(summary.status, 200);
    assert!(summary.body.contains("\"active_blocks\""));
    assert!(summary.body.contains("\"log_events_run\""));
    assert!(summary.body.contains("\"log_dropped\""));
    assert!(summary.body.contains("\"alerts_pending\""));
    assert!(summary.body.contains("\"country\":\"US\""));

    // -------- CSRF on a state-changing request
    let no_csrf = post(
        port,
        "/blocks/add",
        "src=203.0.113.99&minutes=60&reason=test",
        Some(&cookie),
    );
    assert_eq!(no_csrf.status, 403);

    let blocked = post(
        port,
        "/blocks/add",
        &format!("src=203.0.113.99&minutes=60&reason=test&csrf={csrf_token}"),
        Some(&cookie),
    );
    assert_eq!(blocked.status, 303, "{}", blocked.headers);
    assert!(blocked.headers.contains("Location: /blocks?notice=blocked"));
    let blocks_page = get(port, "/blocks", Some(&cookie));
    assert_eq!(blocks_page.status, 200);
    assert!(
        blocks_page
            .body
            .contains("data-confirm=\"Unblock 203.0.113.99?\"")
    );
    assert!(!blocks_page.body.contains("Unblock <button"));
    assert!(blocks_page.body.contains("data-ip=\"203.0.113.99\""));

    let db = Db::open(&layout.db).unwrap();
    let block = db
        .active_block("203.0.113.99".parse().unwrap())
        .unwrap()
        .expect("manual block recorded");
    assert_eq!(block.strike, 0);
    let audit = db.recent_audit_full(20).unwrap();
    assert!(
        audit.iter().any(
            |(_, actor, action, _, _)| actor == "admin:break-glass" && action == "block.manual"
        ),
        "audit: {audit:?}"
    );

    // Implicit addresses cannot be blocked through the UI either.
    let implicit = post(
        port,
        "/blocks/add",
        &format!("src=127.0.0.1&minutes=60&csrf={csrf_token}"),
        Some(&cookie),
    );
    assert_eq!(implicit.status, 303);
    assert!(implicit.headers.contains("notice=implicit"));
    assert!(
        db.active_block("127.0.0.1".parse().unwrap())
            .unwrap()
            .is_none()
    );

    // -------- logout invalidates the cookie
    let out = post(
        port,
        "/logout",
        &format!("csrf={csrf_token}"),
        Some(&cookie),
    );
    assert_eq!(out.status, 303);
    assert!(out.headers.contains("Location: /login"));
    let after = get(port, "/", Some(&cookie));
    assert_eq!(after.status, 303);

    handle.stop();
    std::fs::remove_dir_all(dir).ok();
}

//! First-run, recovery and setup-safety tests (TEST-39/40, non-root parts).

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use rustips::db::Db;

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_rustips")
}

fn temp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "rustips-cli-{}-{}-{}",
        std::process::id(),
        name,
        chrono::Utc::now().timestamp_nanos_opt().unwrap()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn run(dir: &Path, args: &[&str]) -> Output {
    Command::new(binary())
        .env("RUSTIPS_CONFIG", dir.join("config.toml"))
        .env("RUSTIPS_STATE_DIR", dir.join("state"))
        .args(args)
        .output()
        .unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn check_applies_stored_detection_overrides() {
    let dir = temp("overrides");
    let setup = run(&dir, &["setup", "--non-interactive"]);
    assert!(setup.status.success(), "{}", stderr(&setup));

    let db = Db::open(&dir.join("state/rustips.db")).unwrap();
    let mut changes = std::collections::BTreeMap::new();
    changes.insert(
        "detection.http_bad_paths".to_string(),
        "/custom, /probe".to_string(),
    );
    db.set_detection_overrides(&changes, &[]).unwrap();

    let check = run(&dir, &["check"]);
    assert!(check.status.success(), "{}", stderr(&check));
    assert!(
        stdout(&check).contains("overrides: 1 applied"),
        "{}",
        stdout(&check)
    );

    changes.insert("detection.scan_ports".to_string(), "999999".to_string());
    db.set_detection_overrides(&changes, &[]).unwrap();
    let bad = run(&dir, &["check"]);
    assert!(!bad.status.success());
    assert!(stdout(&bad).contains("overrides: FAIL"), "{}", stdout(&bad));

    db.clear_all_detection_overrides().unwrap();
    changes.clear();
    changes.insert("detection.honeypot_enabled".to_string(), "true".to_string());
    db.set_detection_overrides(&changes, &[]).unwrap();
    let no_ports = run(&dir, &["check"]);
    assert!(!no_ports.status.success());
    assert!(
        stdout(&no_ports).contains("honeypot_enabled requires at least one honeypot port"),
        "{}",
        stdout(&no_ports)
    );

    changes.insert(
        "detection.honeypot_ports".to_string(),
        "2323, 9999".to_string(),
    );
    db.set_detection_overrides(&changes, &[]).unwrap();
    let honeypot = run(&dir, &["check"]);
    assert!(honeypot.status.success(), "{}", stderr(&honeypot));
    assert!(
        stdout(&honeypot).contains("overrides: 2 applied"),
        "{}",
        stdout(&honeypot)
    );

    db.clear_all_detection_overrides().unwrap();
    std::fs::remove_dir_all(dir).ok();
}

#[test]
fn setup_is_idempotent_and_never_enables_enforce() {
    let dir = temp("setup");
    let first = run(&dir, &["setup", "--non-interactive"]);
    assert!(first.status.success(), "{}", stderr(&first));
    let config = dir.join("config.toml");
    let db = dir.join("state/rustips.db");
    assert!(config.exists());
    assert!(db.exists());
    let mode = std::fs::metadata(&config).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let db_mode = std::fs::metadata(&db).unwrap().permissions().mode() & 0o777;
    assert_eq!(db_mode, 0o600);
    let text = std::fs::read_to_string(&config).unwrap();
    assert!(text.contains("mode = \"observe\""));
    assert!(!text.contains("mode = \"enforce\""));

    let second = run(&dir, &["setup", "--non-interactive"]);
    assert!(!second.status.success());
    assert!(stderr(&second).contains("already exists"));

    let check = run(&dir, &["check"]);
    assert!(check.status.success(), "{}", stderr(&check));
    std::fs::remove_dir_all(dir).ok();
}

#[test]
fn dry_run_writes_nothing_and_install_service_is_previewed() {
    let dir = temp("dry");
    let output = run(
        &dir,
        &[
            "setup",
            "--non-interactive",
            "--dry-run",
            "--install-service",
        ],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stdout(&output).contains("/usr/local/bin/rustips"));
    assert!(!dir.join("config.toml").exists());
    assert!(!dir.join("state").exists());
    std::fs::remove_dir_all(dir).ok();
}

#[test]
fn missing_config_with_database_enters_recovery() {
    let dir = temp("recovery");
    assert!(run(&dir, &["setup", "--non-interactive"]).status.success());
    let config = dir.join("config.toml");
    let db = dir.join("state/rustips.db");
    assert!(db.exists());
    let before = std::fs::metadata(&db).unwrap().len();
    std::fs::remove_file(&config).unwrap();

    let run_missing = run(&dir, &["run", "--no-web"]);
    assert!(!run_missing.status.success());
    let text = stderr(&run_missing);
    assert!(
        text.contains("recovery") || text.contains("Recovery") || text.contains("setup --recover"),
        "{text}"
    );

    let recovered = run(&dir, &["setup", "--non-interactive", "--recover"]);
    assert!(recovered.status.success(), "{}", stderr(&recovered));
    assert!(config.exists());
    assert!(db.exists());
    let after = std::fs::metadata(&db).unwrap().len();
    assert!(after >= before, "database was replaced");
    std::fs::remove_dir_all(dir).ok();
}

#[test]
fn fresh_requires_confirmation_and_archives_state() {
    let dir = temp("fresh");
    assert!(run(&dir, &["setup", "--non-interactive"]).status.success());
    let refused = run(&dir, &["setup", "--non-interactive", "--fresh"]);
    assert!(!refused.status.success());
    assert!(stderr(&refused).contains("--force"));

    let accepted = run(&dir, &["setup", "--non-interactive", "--fresh", "--force"]);
    assert!(accepted.status.success(), "{}", stderr(&accepted));
    let backups = dir.join("state/backups");
    let archived = std::fs::read_dir(&backups)
        .unwrap()
        .filter_map(Result::ok)
        .any(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with("pre-fresh-")
        });
    assert!(archived, "no pre-fresh archive found");
    std::fs::remove_dir_all(dir).ok();
}

#[test]
fn invalid_config_is_a_hard_error() {
    let dir = temp("invalid");
    assert!(run(&dir, &["setup", "--non-interactive"]).status.success());
    std::fs::write(dir.join("config.toml"), "mode = 42\n").unwrap();
    let output = run(&dir, &["check"]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("config") || stdout(&output).contains("config"));
    std::fs::remove_dir_all(dir).ok();
}

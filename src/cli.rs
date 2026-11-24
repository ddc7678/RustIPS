//! Command-line interface and operator commands.

use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use chrono::Utc;
use clap::{Parser, Subcommand};

use crate::config::{BlockDuration, Config, DEFAULT_CONFIG_TOML, Mode, UnblockEffect};
use crate::daemon;
use crate::db::Db;
use crate::enforce::{Enforcer, NftEnforcer};
use crate::error::{Error, Result};
use crate::model::{Actor, Block, BlockState, Strike};
use crate::net::{self, Cidr};
use crate::paths::{Layout, Startup};
use crate::rules::{Rule, RuleSet};

#[derive(Parser)]
#[command(
    name = "rustips",
    version,
    about = "RustIPS — intrusion prevention for a single host",
    long_about = None
)]
struct Cli {
    /// Configuration file (default /etc/rustips/config.toml).
    #[arg(long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,

    /// State directory (default /var/lib/rustips).
    #[arg(long, global = true, value_name = "DIR")]
    state_dir: Option<PathBuf>,

    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create /etc/rustips/config.toml and the state directory.
    Setup {
        /// Overwrite an existing configuration.
        #[arg(long)]
        force: bool,
        /// Print what would be written, change nothing.
        #[arg(long)]
        dry_run: bool,
        /// Install the systemd unit, admin group and PAM service.
        #[arg(long)]
        install_service: bool,
        /// Accept flags only (no prompts). Present for scripting parity.
        #[arg(long)]
        non_interactive: bool,
        /// Regenerate a missing config, keep the existing database.
        #[arg(long)]
        recover: bool,
        /// Archive existing state and start over (requires --force).
        #[arg(long)]
        fresh: bool,
    },

    /// Validate configuration, permissions, storage and enforcement access.
    Check,

    /// Dump effective state for support and first-run troubleshooting.
    Diagnose,

    /// Configuration helpers.
    Config {
        #[command(subcommand)]
        cmd: ConfigCmd,
    },

    /// Run the daemon (default command).
    Run {
        /// Replay a pcap instead of capturing live traffic.
        #[arg(long, value_name = "FILE")]
        pcap: Option<PathBuf>,
        /// Replay without honouring capture timestamps.
        #[arg(long)]
        fast_replay: bool,
        /// Force observe mode, whatever the configuration says.
        #[arg(long)]
        observe: bool,
        /// Do not start the embedded web UI.
        #[arg(long)]
        no_web: bool,
        /// Override the UI bind address (default from config, then 127.0.0.1).
        #[arg(long, value_name = "ADDR")]
        web_bind: Option<String>,
        /// Override the UI port (default from config, then 10707).
        #[arg(long, value_name = "PORT")]
        web_port: Option<u16>,
    },

    /// Authentication helpers: test PAM and mint a break-glass token.
    Auth {
        #[command(subcommand)]
        cmd: AuthCmd,
    },

    /// Show mode, counts and recent activity.
    Status,

    /// Block an address now.
    Block {
        ip: String,
        #[arg(long, default_value = "24h")]
        duration: String,
        #[arg(long, default_value = "manual block")]
        reason: String,
    },

    /// Remove a block and record it as manually unblocked.
    Unblock { ip: String },

    /// Add an allowlist entry.
    Allow {
        cidr: String,
        #[arg(long, default_value = "")]
        label: String,
        /// Also remove an existing block for this entry.
        #[arg(long)]
        unblock: bool,
    },

    /// List allowlist entries.
    Allowlist {
        #[arg(long)]
        json: bool,
    },

    /// Show recent detections.
    Detections {
        #[arg(long, default_value_t = 20)]
        limit: u32,
    },

    /// Export blocks, strikes, allowlist and rules as JSON.
    Export {
        #[arg(long, value_name = "FILE")]
        out: Option<PathBuf>,
    },

    /// Import a JSON export.
    Import { file: PathBuf },

    /// Remove every block and the nftables table.
    Flush {
        /// Required: this removes protection for every blocked source.
        #[arg(long)]
        yes: bool,
    },

    /// Inspect host-log ingestion and parser output.
    Logs {
        #[command(subcommand)]
        cmd: LogsCmd,
    },

    /// Inspect and validate the disposition rules.
    Rules {
        #[command(subcommand)]
        cmd: RulesCmd,
    },

    /// Manage the disposition-only GeoIP/ASN database.
    Geo {
        #[command(subcommand)]
        cmd: GeoCmd,
    },
}

#[derive(Subcommand)]
enum GeoCmd {
    /// Download, verify and install the country and ASN indexes.
    Update {
        /// Offline country IPv4 CSV (requires all four --*-file options).
        #[arg(long, value_name = "FILE")]
        country_v4: Option<PathBuf>,
        #[arg(long, value_name = "FILE")]
        country_v6: Option<PathBuf>,
        #[arg(long, value_name = "FILE")]
        asn_v4: Option<PathBuf>,
        #[arg(long, value_name = "FILE")]
        asn_v6: Option<PathBuf>,
    },
    /// Show the current index generation and last update result.
    Status,
    /// Look up one address in the loaded indexes.
    Lookup { ip: IpAddr },
}

#[derive(Subcommand)]
enum RulesCmd {
    /// Validate the stored rule set and report precise errors.
    Check,
    /// List the stored rules in evaluation order.
    List,
    /// Print disabled sample country/ASN rules as an importable document.
    Samples {
        /// Print JSON instead of a table.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum LogsCmd {
    /// Dry-run the parsers on the journal; writes nothing to the database.
    Test {
        /// journalctl time window, e.g. 10m, 1h, "2026-11-19 12:00".
        #[arg(long, default_value = "10m")]
        since: String,
        #[arg(long, default_value_t = 200)]
        limit: usize,
        /// Print one JSON object per parsed event.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum ConfigCmd {
    /// Alias for `rustips check`.
    Check,
}

#[derive(Subcommand)]
enum AuthCmd {
    /// Verify PAM and group authorisation for one system account.
    Test {
        /// System username (not a RustIPS-specific account).
        #[arg(long)]
        user: String,
    },
    /// Create a one-time break-glass token for the web UI.
    Breakglass {
        /// Lifetime of the token in minutes.
        #[arg(long, default_value_t = 30)]
        minutes: u64,
    },
}

pub fn main() -> i32 {
    // CLI tools should die quietly when a pipeline closes, not panic on the
    // failed write to stdout.
    // SAFETY: restoring the default disposition for SIGPIPE has no preconditions.
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };

    let cli = Cli::parse();
    init_logging();

    let layout = Layout::with_overrides(cli.config, cli.state_dir);
    let result = match cli.cmd.unwrap_or(Cmd::Run {
        pcap: None,
        fast_replay: false,
        observe: false,
        no_web: false,
        web_bind: None,
        web_port: None,
    }) {
        Cmd::Setup {
            force,
            dry_run,
            install_service,
            non_interactive,
            recover,
            fresh,
        } => cmd_setup(
            &layout,
            SetupOpts {
                force,
                dry_run,
                install_service,
                non_interactive,
                recover,
                fresh,
            },
        ),
        Cmd::Check => cmd_check(&layout),
        Cmd::Diagnose => cmd_diagnose(&layout),
        Cmd::Config { cmd } => match cmd {
            ConfigCmd::Check => cmd_check(&layout),
        },
        Cmd::Run {
            pcap,
            fast_replay,
            observe,
            no_web,
            web_bind,
            web_port,
        } => cmd_run(
            &layout,
            pcap,
            fast_replay,
            observe,
            no_web,
            web_bind,
            web_port,
        ),
        Cmd::Auth { cmd } => match cmd {
            AuthCmd::Test { user } => cmd_auth_test(&layout, &user),
            AuthCmd::Breakglass { minutes } => cmd_auth_breakglass(&layout, minutes),
        },
        Cmd::Status => cmd_status(&layout),
        Cmd::Block {
            ip,
            duration,
            reason,
        } => cmd_block(&layout, &ip, &duration, &reason),
        Cmd::Unblock { ip } => cmd_unblock(&layout, &ip),
        Cmd::Allow {
            cidr,
            label,
            unblock,
        } => cmd_allow(&layout, &cidr, &label, unblock),
        Cmd::Allowlist { json } => cmd_allowlist(&layout, json),
        Cmd::Detections { limit } => cmd_detections(&layout, limit),
        Cmd::Export { out } => cmd_export(&layout, out),
        Cmd::Import { file } => cmd_import(&layout, &file),
        Cmd::Flush { yes } => cmd_flush(&layout, yes),
        Cmd::Logs { cmd } => match cmd {
            LogsCmd::Test { since, limit, json } => cmd_logs_test(&layout, &since, limit, json),
        },
        Cmd::Rules { cmd } => match cmd {
            RulesCmd::Check => cmd_rules_check(&layout),
            RulesCmd::List => cmd_rules_list(&layout),
            RulesCmd::Samples { json } => cmd_rules_samples(json),
        },
        Cmd::Geo { cmd } => match cmd {
            GeoCmd::Update {
                country_v4,
                country_v6,
                asn_v4,
                asn_v6,
            } => cmd_geo_update(&layout, country_v4, country_v6, asn_v4, asn_v6),
            GeoCmd::Status => cmd_geo_status(&layout),
            GeoCmd::Lookup { ip } => cmd_geo_lookup(&layout, ip),
        },
    };

    match result {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

fn init_logging() {
    use std::io::IsTerminal;
    use tracing_subscriber::EnvFilter;
    let filter = std::env::var("RUSTIPS_LOG").unwrap_or_else(|_| "info".to_string());
    // Under systemd stderr is the journal, not a terminal; escape codes would
    // otherwise end up in stored log events.
    let ansi = std::io::stderr().is_terminal();
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(filter))
        .with_target(false)
        .with_ansi(ansi)
        .with_writer(std::io::stderr)
        .try_init();
}

// ---------------------------------------------------------------------- setup

struct SetupOpts {
    force: bool,
    dry_run: bool,
    install_service: bool,
    non_interactive: bool,
    recover: bool,
    fresh: bool,
}

fn cmd_setup(layout: &Layout, opts: SetupOpts) -> Result<()> {
    let _ = opts.non_interactive;
    let startup = layout.startup();

    if startup == Startup::Recovery && !opts.recover && !opts.fresh {
        return Err(Error::Recovery {
            path: layout.config.clone(),
            db: layout.db.clone(),
        });
    }
    if layout.has_config() && !opts.force && !opts.recover {
        return Err(Error::Invalid(format!(
            "{} already exists; use --force to overwrite it",
            layout.config.display()
        )));
    }
    if opts.fresh && !opts.force {
        return Err(Error::Invalid(
            "--fresh archives existing state; pass --force to confirm".into(),
        ));
    }

    if opts.dry_run {
        println!("would create {}", layout.config.display());
        println!("would create {}", layout.state_dir.display());
        if opts.fresh && layout.has_state() {
            println!("would archive {}", layout.state_dir.display());
        }
        if opts.install_service {
            println!("would install /usr/local/bin/rustips");
            println!("would install /etc/systemd/system/rustips.service");
            println!("would create group rustips-admin if missing");
            println!("would install /etc/pam.d/rustips if absent");
        }
        return Ok(());
    }

    if !is_root()
        && (layout.config == Path::new(crate::paths::DEFAULT_CONFIG)
            || layout.state_dir == Path::new(crate::paths::DEFAULT_STATE_DIR))
    {
        return Err(Error::Permission(
            "writing /etc/rustips and /var/lib/rustips; use sudo, or --config/--state-dir \
             (or RUSTIPS_CONFIG/RUSTIPS_STATE_DIR) for a test install"
                .into(),
        ));
    }

    if opts.fresh && layout.has_state() {
        let stamp = Utc::now().format("%Y%m%dT%H%M%SZ");
        let dest = layout
            .state_dir
            .join("backups")
            .join(format!("pre-fresh-{stamp}"));
        std::fs::create_dir_all(&dest)?;
        for name in ["rustips.db", "rustips.db-wal", "rustips.db-shm"] {
            let src = layout.state_dir.join(name);
            if src.exists() {
                std::fs::rename(&src, dest.join(name))?;
            }
        }
        println!("archived previous state to {}", dest.display());
    }

    layout.ensure_config_dir()?;
    layout.ensure_state_dir()?;

    // Write config with restrictive permissions from the start.
    let mut f = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&layout.config)?
    };
    f.write_all(DEFAULT_CONFIG_TOML.as_bytes())?;
    f.flush()?;
    crate::paths::set_mode(&layout.config, 0o600)?;

    // Create and validate the database, and seed the implicit allowlist.
    let db = Db::open(&layout.db)?;
    db.seed_implicit_allowlist()?;
    db.audit(&Actor::Cli, "setup", "", "configuration created")?;

    println!("wrote {}", layout.config.display());
    if startup == Startup::Recovery {
        println!("recovered existing state at {}", layout.state_dir.display());
    } else {
        println!("created {}", layout.state_dir.display());
    }

    if opts.install_service {
        install_service(layout, opts.force)?;
    }

    println!();
    println!("Next:");
    if opts.install_service {
        println!("  1. start the service:");
        println!("       sudo systemctl enable --now rustips");
        println!("  2. check it:");
        println!("       sudo rustips check && sudo rustips status");
        println!("  3. watch detections:");
        println!("       sudo rustips detections");
        println!("  4. open the UI through a tunnel:");
        println!("       ssh -L 10707:127.0.0.1:10707 <user>@<this-host>");
        println!("       then browse http://127.0.0.1:10707/");
        println!("  5. optional country/ASN indexes:");
        println!("       sudo rustips geo update");
    } else {
        println!("  1. check the configuration:");
        println!("       sudo rustips check");
        println!("  2. run it in the foreground:");
        println!("       sudo rustips run");
        println!("  3. open the UI through a tunnel:");
        println!("       ssh -L 10707:127.0.0.1:10707 <user>@<this-host>");
        println!("       then browse http://127.0.0.1:10707/");
        println!("  4. if PAM is unavailable, mint a token:");
        println!("       sudo rustips auth breakglass");
        println!("  5. optional country/ASN indexes:");
        println!("       sudo rustips geo update");
    }
    println!();
    println!("Add your own account to the administrator group before logging in:");
    println!("       sudo usermod -aG rustips-admin <your-user>");
    println!("(log out and back in so the new group is in your session)");
    println!();
    println!("The first run is observe mode: detections are recorded, nothing is blocked.");
    println!("Switch to enforce only after reviewing detections: set mode = \"enforce\".");
    println!();
    println!("The UI binds 127.0.0.1:10707 and authenticates against the host's PAM stack;");
    println!("membership of `rustips-admin` is required.");
    Ok(())
}

const UNIT_TEMPLATE: &str = r#"[Unit]
Description=RustIPS intrusion prevention system
After=network-online.target nftables.service
Wants=network-online.target
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=simple
ExecStart={exe} run
Restart=always
RestartSec=2
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
NoNewPrivileges=yes
UMask=0077
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
RestrictNamespaces=yes
LockPersonality=yes
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK AF_PACKET
ReadWritePaths=/var/lib/rustips
SupplementaryGroups=systemd-journal
MemoryMax=512M
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
"#;

const PAM_TEMPLATE: &str = r#"#%PAM-1.0
# RustIPS web UI authentication. Managed by `rustips setup`.
auth     include common-auth
account  include common-account
"#;

fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() == 0 }
}

fn install_service(layout: &Layout, force: bool) -> Result<()> {
    if !is_root() {
        return Err(Error::Permission("installing the systemd unit".into()));
    }
    let installed = Path::new("/usr/local/bin/rustips");
    let source = std::env::current_exe()?;
    if install_binary(&source, installed)? {
        println!("installed {}", installed.display());
    }
    let unit_path = Path::new("/etc/systemd/system/rustips.service");
    let contents = UNIT_TEMPLATE.replace("{exe}", &installed.display().to_string());

    if unit_path.exists() && !force {
        println!(
            "{} already exists; left unchanged (use --force to replace)",
            unit_path.display()
        );
    } else {
        write_atomic(unit_path, &contents, 0o644)?;
        println!("wrote {}", unit_path.display());
    }

    // Group creation is idempotent.
    let _ = std::process::Command::new("groupadd")
        .args(["-f", "rustips-admin"])
        .status();

    let pam_path = Path::new("/etc/pam.d/rustips");
    if pam_path.exists() {
        println!("{} already exists; left unchanged", pam_path.display());
    } else {
        write_atomic(pam_path, PAM_TEMPLATE, 0o644)?;
        println!("wrote {}", pam_path.display());
    }

    let _ = std::process::Command::new("systemctl")
        .args(["daemon-reload"])
        .status();

    println!("service installed. It is not enabled or started.");
    println!("config: {}", layout.config.display());
    Ok(())
}

/// Copy the running binary to the system path atomically. Returns false when
/// the source and destination are already the same file.
fn install_binary(source: &Path, dest: &Path) -> Result<bool> {
    let same = std::fs::canonicalize(source)
        .ok()
        .zip(std::fs::canonicalize(dest).ok())
        .map(|(a, b)| a == b)
        .unwrap_or(false);
    if same {
        return Ok(false);
    }
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let temp = dest.with_extension("tmp");
    std::fs::copy(source, &temp)?;
    crate::paths::set_mode(&temp, 0o755)?;
    std::fs::rename(&temp, dest)?;
    Ok(true)
}

fn write_atomic(path: &Path, contents: &str, mode: u32) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = path.with_extension("tmp");
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(&tmp)?;
        f.write_all(contents.as_bytes())?;
    }
    std::fs::rename(&tmp, path)?;
    crate::paths::set_mode(path, mode)?;
    Ok(())
}

// ---------------------------------------------------------------------- run/check

/// The Detectors UI stores parameter overrides in SQLite. They are applied on
/// every daemon start, after the config file, so the effective config shown in
/// the UI and used by the detectors is identical.
fn apply_stored_detection_overrides(layout: &Layout, cfg: &mut Config) -> Result<usize> {
    if !layout.db.exists() {
        return Ok(0);
    }
    let overrides = Db::open(&layout.db)?.detection_overrides()?;
    if overrides.is_empty() {
        return Ok(0);
    }
    crate::params::apply_overrides(cfg, &overrides)
        .map_err(|e| Error::Config(format!("stored detection overrides: {e}")))?;
    Ok(overrides.len())
}

fn load_config(layout: &Layout) -> Result<Config> {
    match layout.startup() {
        Startup::Unconfigured => Err(Error::ConfigMissing {
            path: layout.config.clone(),
        }),
        Startup::Recovery => Err(Error::Recovery {
            path: layout.config.clone(),
            db: layout.db.clone(),
        }),
        Startup::Normal => {
            let mut cfg = Config::load(&layout.config)?;
            let applied = apply_stored_detection_overrides(layout, &mut cfg)?;
            if applied > 0 {
                tracing::info!(
                    count = applied,
                    "applied stored detection parameter overrides"
                );
            }
            Ok(cfg)
        }
    }
}

fn cmd_run(
    layout: &Layout,
    pcap: Option<PathBuf>,
    fast_replay: bool,
    observe: bool,
    no_web: bool,
    web_bind: Option<String>,
    web_port: Option<u16>,
) -> Result<()> {
    let cfg = load_config(layout)?;
    if pcap.is_some() && !observe && cfg.mode == Mode::Enforce {
        tracing::warn!("replaying a capture in enforce mode will apply real blocks");
    }
    daemon::run(
        layout,
        cfg,
        daemon::Options {
            pcap,
            fast_replay,
            force_observe: observe,
            no_web,
            web_bind,
            web_port,
        },
    )
}

/// `rustips auth test --user NAME`: exercise the same PAM service and group
/// check the UI uses, without touching a browser.
fn cmd_auth_test(layout: &Layout, user: &str) -> Result<()> {
    let cfg = load_config(layout)?;
    if !crate::auth::pam_service_file(&cfg.web.pam_service) {
        return Err(Error::NotFound(format!(
            "/etc/pam.d/{} is missing; run `sudo rustips setup --install-service`",
            cfg.web.pam_service
        )));
    }
    let password = read_password(&format!("Password for {user}: "))?;
    let outcome =
        crate::auth::authenticate(&cfg.web.pam_service, user, &password, &cfg.web.admin_group);
    let result = outcome.audit_result();
    if let Ok(db) = Db::open(&layout.db) {
        let _ = db.audit(&Actor::Login(user.to_string()), "auth.test", "cli", &result);
    }
    println!("user:   {user}");
    println!("pam:    {}", cfg.web.pam_service);
    println!("group:  {}", cfg.web.admin_group);
    println!("result: {result}");
    if outcome.is_success() {
        Ok(())
    } else {
        Err(Error::Permission(outcome.user_message().to_string()))
    }
}

fn cmd_auth_breakglass(layout: &Layout, minutes: u64) -> Result<()> {
    if !is_root() {
        return Err(Error::Permission(
            "break-glass tokens are root-only; run with sudo".into(),
        ));
    }
    if !(1..=1440).contains(&minutes) {
        return Err(Error::Invalid(
            "--minutes must be between 1 and 1440".into(),
        ));
    }
    let bg = crate::auth::create_breakglass(
        &layout.state_dir,
        std::time::Duration::from_secs(minutes * 60),
    )?;
    if let Ok(db) = Db::open(&layout.db) {
        let _ = db.audit(
            &Actor::Cli,
            "auth.breakglass.create",
            "",
            &format!("expires {}", bg.expires_at.to_rfc3339()),
        );
    }
    println!("Break-glass token (one use, expires in {minutes} min):");
    println!();
    println!("  {}", bg.token);
    println!();
    println!("file:    {}", bg.path.display());
    println!("expires: {}", bg.expires_at.to_rfc3339());
    println!();
    println!("Open the UI, leave the password empty, and paste the token.");
    Ok(())
}

fn read_password(prompt: &str) -> Result<String> {
    use std::io::{BufRead, Write};
    use std::os::unix::io::AsRawFd;
    eprint!("{prompt}");
    std::io::stderr().flush().ok();

    if let Ok(tty) = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
    {
        let fd = tty.as_raw_fd();
        let mut term: libc::termios = unsafe { std::mem::zeroed() };
        let have = unsafe { libc::tcgetattr(fd, &mut term) } == 0;
        let original = term;
        if have {
            term.c_lflag &= !libc::ECHO;
            unsafe { libc::tcsetattr(fd, libc::TCSANOW, &term) };
        }
        let mut reader = std::io::BufReader::new(tty);
        let mut line = String::new();
        let result = reader.read_line(&mut line);
        if have {
            unsafe { libc::tcsetattr(fd, libc::TCSANOW, &original) };
        }
        eprintln!();
        result?;
        return Ok(line.trim_end_matches(['\r', '\n']).to_string());
    }

    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

fn cmd_check(layout: &Layout) -> Result<()> {
    let mut problems = 0;
    println!("RustIPS {}", crate::VERSION);
    println!("config:   {}", layout.config.display());
    println!("state:    {}", layout.state_dir.display());
    println!("database: {}", layout.db.display());

    let cfg = match Config::load(&layout.config) {
        Ok(mut cfg) => {
            println!("config:   OK (mode {})", cfg.mode);
            match apply_stored_detection_overrides(layout, &mut cfg) {
                Ok(0) => println!("overrides: none stored"),
                Ok(count) => println!("overrides: {count} applied"),
                Err(e) => {
                    println!("overrides: FAIL: {e}");
                    problems += 1;
                }
            }
            cfg
        }
        Err(e) => {
            println!("config:   FAIL: {e}");
            return Err(e);
        }
    };

    if layout.state_dir.exists() {
        let probe = layout.state_dir.join(".check-write");
        match std::fs::write(&probe, b"ok").and_then(|_| std::fs::remove_file(&probe)) {
            Ok(()) => println!("storage:  OK (writable)"),
            Err(e) => {
                println!("storage:  FAIL: {e}");
                problems += 1;
            }
        }
    } else {
        println!("storage:  missing; run `rustips setup`");
        problems += 1;
    }

    match Db::open(&layout.db) {
        Ok(db) => {
            let n = db.active_block_count().unwrap_or(0);
            println!("database: OK ({n} active blocks)");
            match db.list_rules() {
                Ok(rules) if !rules.is_empty() => {
                    match RuleSet::compile(rules, &cfg.ladder.steps) {
                        Ok(set) => println!("rules:    OK ({} rules)", set.len()),
                        Err(errors) => {
                            for error in errors {
                                println!("rules:    FAIL: {error}");
                            }
                            problems += 1;
                        }
                    }
                }
                Ok(_) => {
                    println!("rules:    WARNING: no stored rules; the shipped defaults will apply")
                }
                Err(e) => {
                    println!("rules:    FAIL: {e}");
                    problems += 1;
                }
            }
        }
        Err(e) => {
            println!("database: FAIL: {e}");
            problems += 1;
        }
    }

    match crate::capture::resolve_interfaces(&cfg.capture.interfaces) {
        Ok(names) => {
            for name in names {
                match net::interface_index(&name) {
                    Ok(_) => println!("capture:  OK ({name})"),
                    Err(e) => {
                        println!("capture:  FAIL: interface {name}: {e}");
                        problems += 1;
                    }
                }
            }
        }
        Err(e) => {
            println!("capture:  FAIL: {e}");
            problems += 1;
        }
    }

    let nft = NftEnforcer::new(
        &cfg.enforcement.table,
        &cfg.enforcement.chain_hook,
        cfg.enforcement.priority,
    );
    if nft.available() {
        println!("nftables: present");
    } else {
        println!("nftables: not found");
        if cfg.mode == Mode::Enforce {
            problems += 1;
        }
    }

    let firewall_settings = Db::open(&layout.db)
        .ok()
        .map(|db| crate::firewall::settings(&db, &cfg))
        .unwrap_or_else(|| cfg.firewall.clone());
    if firewall_settings.enabled {
        println!(
            "firewall: enabled (discover={}, refresh={}s, log_drops={}, action={})",
            firewall_settings.discover_services,
            firewall_settings.refresh_secs,
            firewall_settings.log_drops,
            if firewall_settings.reject {
                "reject"
            } else {
                "drop"
            }
        );
        if firewall_settings.discover_services {
            match crate::firewall::discover() {
                Ok(sockets) => {
                    println!("firewall: {} listening socket(s) discovered", sockets.len())
                }
                Err(e) => {
                    println!("firewall: FAIL: service discovery: {e}");
                    problems += 1;
                }
            }
        }
        if cfg.mode != Mode::Enforce {
            println!("firewall: WARNING: enabled but the daemon is in observe mode");
        }
    } else {
        println!("firewall: disabled (optional service firewall)");
    }

    if cfg.mode == Mode::Enforce {
        if is_root() {
            println!("privilege: root (enough to capture and enforce)");
        } else {
            println!("privilege: not root; enforce mode needs CAP_NET_RAW/CAP_NET_ADMIN");
            problems += 1;
        }
    }

    let geo_status = crate::geo::update::read_status(&Db::open(&layout.db)?);
    if geo_status.country.is_some() || geo_status.asn.is_some() {
        println!(
            "geo:      country {}, asn {}",
            if geo_status.country.is_some() {
                "loaded"
            } else {
                "absent"
            },
            if geo_status.asn.is_some() {
                "loaded"
            } else {
                "absent"
            }
        );
    } else if cfg.geo.enabled {
        println!("geo:      WARNING: enabled but no index; run `rustips geo update`");
    } else {
        println!("geo:      not configured (geo rules will not match)");
    }

    let enabled_targets = Db::open(&layout.db)
        .ok()
        .and_then(|db| db.enabled_alert_targets().ok())
        .unwrap_or_default();
    if enabled_targets.is_empty() {
        println!("alerts:   no enabled webhook targets");
    } else {
        match std::process::Command::new("curl").arg("--version").output() {
            Ok(out) if out.status.success() => println!(
                "alerts:   OK ({} enabled target(s), curl available)",
                enabled_targets.len()
            ),
            _ => println!("alerts:   WARNING: targets enabled but curl is not available"),
        }
    }

    if cfg.logs.enabled {
        match std::process::Command::new("journalctl")
            .arg("--version")
            .output()
        {
            Ok(out) if out.status.success() => {
                println!("logs:     OK (journald ingestion enabled)");
            }
            _ => {
                println!("logs:     WARNING: journalctl not found; ingestion will report degraded")
            }
        }
    } else {
        println!("logs:     disabled");
    }

    if cfg.web.enabled {
        let bind = format!("{}:{}", cfg.web.bind, cfg.web.port);
        println!(
            "web:      {bind} (PAM service {}, group {})",
            cfg.web.pam_service, cfg.web.admin_group
        );
        if !cfg
            .web
            .bind
            .parse::<IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false)
        {
            println!("web:      WARNING: non-loopback bind; use an SSH tunnel or TLS");
        }
        if !crate::auth::pam_service_file(&cfg.web.pam_service) {
            println!(
                "auth:     WARNING: /etc/pam.d/{} missing; only break-glass can log in",
                cfg.web.pam_service
            );
        } else if !crate::auth::pam_loaded() {
            println!("auth:     WARNING: libpam.so.0 could not be loaded");
        } else {
            println!("auth:     OK (PAM service {})", cfg.web.pam_service);
        }
    } else {
        println!("web:      disabled");
    }

    if problems == 0 {
        println!("result:   OK");
        Ok(())
    } else {
        Err(Error::Invalid(format!("{problems} problem(s) found")))
    }
}

fn cmd_logs_test(layout: &Layout, since: &str, limit: usize, json: bool) -> Result<()> {
    if since.is_empty() || since.len() > 128 || since.chars().any(char::is_control) {
        return Err(Error::Config(
            "--since is not a valid journal time window".into(),
        ));
    }
    let limit = limit.clamp(1, 10_000);
    // systemd accepts `-10m`; the documented CLI form is `10m`.
    let since_arg = if since
        .chars()
        .all(|c| c.is_ascii_digit() || "smhdw".contains(c))
    {
        format!("-{since}")
    } else {
        since.to_string()
    };
    let output = std::process::Command::new("journalctl")
        .args(["-o", "json", "--no-pager", "--since", &since_arg])
        .arg("-n")
        .arg(limit.to_string())
        .output()
        .map_err(|e| Error::Other(format!("cannot run journalctl: {e}")))?;
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        return Err(Error::Other(format!(
            "journalctl failed: {} (run as root or add the user to systemd-journal)",
            err.trim()
        )));
    }

    // Preview with the installed settings when possible, so redaction and the
    // message cap match what the daemon would store.
    let cfg = Config::load(&layout.config).unwrap_or_else(|_| {
        Config::parse(Path::new("default"), DEFAULT_CONFIG_TOML)
            .expect("the built-in default configuration is valid")
    });
    let mut shown = 0usize;
    if !json {
        println!(
            "{:<20} {:<8} {:<14} {:<26} {:<12} {:<15} MESSAGE",
            "TIME", "ORIGIN", "PARSER", "TEMPLATE", "USER", "SOURCE IP"
        );
    }
    for line in output.stdout.split(|b| *b == b'\n') {
        if line.is_empty() {
            continue;
        }
        let Some(record) = crate::logs::parse::journal_record(line) else {
            continue;
        };
        let event = crate::logs::parse::event_from_record(
            &record,
            cfg.logs.max_message_bytes,
            &cfg.logs.redact,
        );
        if json {
            println!(
                "{}",
                serde_json::to_string(&event).unwrap_or_else(|_| "{}".into())
            );
        } else {
            let message: String = event.message.chars().take(80).collect();
            println!(
                "{:<20} {:<8} {:<14} {:<26} {:<12} {:<15} {}",
                event.ts.format("%Y-%m-%d %H:%M:%S"),
                event.origin.as_str(),
                event.parser,
                event.template,
                event.user.as_deref().unwrap_or("-"),
                event
                    .src_ip
                    .map(|ip| ip.to_string())
                    .unwrap_or_else(|| "-".into()),
                message
            );
        }
        shown += 1;
        if shown >= limit {
            break;
        }
    }
    if shown == 0 {
        eprintln!("no journal entries matched the window");
    } else if !json {
        eprintln!("{shown} event(s); nothing was written to the database");
    }
    Ok(())
}

fn cmd_rules_check(layout: &Layout) -> Result<()> {
    let cfg = Config::load(&layout.config)?;
    let db = Db::open(&layout.db)?;
    let rules = db.list_rules()?;
    if rules.is_empty() {
        println!("rules: none stored; the shipped defaults will apply on start");
        return Ok(());
    }
    match RuleSet::compile(rules, &cfg.ladder.steps) {
        Ok(set) => {
            println!("rules: OK ({} rules)", set.len());
            Ok(())
        }
        Err(errors) => {
            for error in &errors {
                eprintln!("rules: FAIL: {error}");
            }
            Err(Error::Invalid(format!(
                "{} rule error(s); the daemon would keep the last-good set",
                errors.len()
            )))
        }
    }
}

fn cmd_rules_list(layout: &Layout) -> Result<()> {
    let db = Db::open(&layout.db)?;
    let rules = db.list_rules()?;
    if rules.is_empty() {
        println!("no stored rules; the shipped defaults will apply on start");
        return Ok(());
    }
    println!(
        "{:<4} {:<8} {:<8} {:<8} {:<22} MATCH",
        "ID", "ENABLED", "PRIO", "SEVERITY", "ACTION"
    );
    for rule in rules {
        println!(
            "{:<4} {:<8} {:<8} {:<8} {:<22} {}",
            rule.id,
            if rule.enabled { "yes" } else { "no" },
            rule.priority,
            rule.severity.as_str(),
            rule.action_label(),
            rule.match_label()
        );
        println!("     {}", rule.name);
    }
    Ok(())
}

fn cmd_geo_update(
    layout: &Layout,
    country_v4: Option<PathBuf>,
    country_v6: Option<PathBuf>,
    asn_v4: Option<PathBuf>,
    asn_v6: Option<PathBuf>,
) -> Result<()> {
    let cfg = Config::load(&layout.config)?;
    let db = Db::open(&layout.db)?;
    let any_local =
        country_v4.is_some() || country_v6.is_some() || asn_v4.is_some() || asn_v6.is_some();
    let report = if any_local {
        let (Some(country_v4), Some(country_v6), Some(asn_v4), Some(asn_v6)) =
            (country_v4, country_v6, asn_v4, asn_v6)
        else {
            return Err(Error::Invalid(
                "local update needs all four CSVs: --country-v4, --country-v6, --asn-v4, --asn-v6"
                    .into(),
            ));
        };
        crate::geo::update::update_from_files(
            &layout.state_dir,
            &crate::geo::update::LocalFiles {
                country_v4,
                country_v6,
                asn_v4,
                asn_v6,
            },
        )?
    } else {
        let previous = crate::geo::update::read_status(&db);
        crate::geo::update::update_from_network(&cfg, &layout.state_dir, &previous)?
    };

    let now = Utc::now();
    let mut status = crate::geo::update::read_status(&db);
    status.last_check = Some(now);
    status.last_success = Some(now);
    status.last_error = None;
    status.next_check = Some(now + chrono::Duration::hours(cfg.geo.update_hours.max(1) as i64));
    if !report.unchanged {
        status.country = report
            .country
            .as_ref()
            .map(|stats| crate::geo::update::stats_status(stats, now));
        status.asn = report
            .asn
            .as_ref()
            .map(|stats| crate::geo::update::stats_status(stats, now));
    }
    status.sources = report.sources.clone();
    crate::geo::update::write_status(&db, &status)?;
    db.set_setting("geo.reload", &serde_json::json!(Utc::now().to_rfc3339()))?;
    db.audit(
        &Actor::Cli,
        "geo.update",
        "",
        &format!(
            "country={:?} asn={:?}",
            report.country.as_ref().map(|s| s.sha256.clone()),
            report.asn.as_ref().map(|s| s.sha256.clone())
        ),
    )?;
    if report.unchanged {
        println!("geo checksums unchanged; keeping the current indexes");
    }
    if let Some(stats) = &report.country {
        println!(
            "country: {} records (v4 {}, v6 {}), {} bytes, sha256 {}",
            stats.v4 + stats.v6,
            stats.v4,
            stats.v6,
            stats.bytes,
            stats.sha256
        );
    }
    if let Some(stats) = &report.asn {
        println!(
            "asn:     {} records (v4 {}, v6 {}), {} bytes, sha256 {}",
            stats.v4 + stats.v6,
            stats.v4,
            stats.v6,
            stats.bytes,
            stats.sha256
        );
    }
    println!(
        "geo indexes installed under {}",
        layout.state_dir.join("geo").display()
    );
    Ok(())
}

fn cmd_geo_lookup(layout: &Layout, ip: IpAddr) -> Result<()> {
    let data = crate::geo::load_from_dir(&layout.state_dir);
    if data.is_empty() {
        return Err(Error::NotFound(
            "no geo index; run `rustips geo update` first".into(),
        ));
    }
    let info = data.lookup(ip);
    println!(
        "{ip}: country={} asn={}",
        info.country.as_deref().unwrap_or("unknown"),
        info.asn
            .map(|asn| asn.to_string())
            .unwrap_or_else(|| "unknown".into())
    );
    Ok(())
}

fn cmd_geo_status(layout: &Layout) -> Result<()> {
    let db = Db::open(&layout.db)?;
    let status = crate::geo::update::read_status(&db);
    for (label, index) in [("country", &status.country), ("asn", &status.asn)] {
        match index {
            Some(index) => println!(
                "{label}:  loaded (v4 {}, v6 {}, {}, sha256 {}, loaded {})",
                index.v4,
                index.v6,
                human_bytes(index.bytes),
                &index.sha256[..12.min(index.sha256.len())],
                index.loaded_at.format("%Y-%m-%d %H:%M:%SZ")
            ),
            None => println!("{label}:  not configured"),
        }
    }
    if let Some(at) = status.last_check {
        println!("last check:   {}", at.format("%Y-%m-%d %H:%M:%SZ"));
    }
    if let Some(at) = status.last_success {
        println!("last success: {}", at.format("%Y-%m-%d %H:%M:%SZ"));
    }
    if let Some(at) = status.next_check {
        println!("next check:   {}", at.format("%Y-%m-%d %H:%M:%SZ"));
    }
    if let Some(error) = &status.last_error {
        println!("last error:   {error}");
    }
    Ok(())
}

fn cmd_rules_samples(json: bool) -> Result<()> {
    let rules = crate::rules::sample_geo_rules();
    if json {
        let document = serde_json::json!({
            "format": "rustips-rules",
            "version": 1,
            "exported_at": Utc::now(),
            "rules": rules,
        });
        println!("{}", serde_json::to_string_pretty(&document)?);
        return Ok(());
    }
    println!("Sample country/ASN rules (all disabled; load and review before enabling):");
    for rule in rules {
        println!(
            "  {:<45} {:<22} {}",
            rule.name,
            rule.action_label(),
            rule.match_label()
        );
        println!("      {}", rule.description);
    }
    Ok(())
}

fn cmd_diagnose(layout: &Layout) -> Result<()> {
    println!("RustIPS {}", crate::VERSION);
    println!("config:   {}", layout.config.display());
    println!("state:    {}", layout.state_dir.display());
    println!("database: {}", layout.db.display());
    println!("startup:  {:?}", layout.startup());
    println!("root:     {}", if is_root() { "yes" } else { "no" });

    let cfg = match Config::load(&layout.config) {
        Ok(mut cfg) => {
            match apply_stored_detection_overrides(layout, &mut cfg) {
                Ok(0) => println!("overrides: none stored"),
                Ok(count) => println!("overrides: {count} stored and applied"),
                Err(e) => println!("overrides: ERROR: {e}"),
            }
            println!("mode:     {}", cfg.mode);
            println!(
                "capture:  configured {:?}; auto resolves to {:?}",
                cfg.capture.interfaces,
                net::default_interface()
            );
            match crate::capture::resolve_interfaces(&cfg.capture.interfaces) {
                Ok(names) => println!("capture:  resolved {names:?}"),
                Err(e) => println!("capture:  ERROR: {e}"),
            }
            println!(
                "web:      {}:{} (PAM {}, group {})",
                cfg.web.bind, cfg.web.port, cfg.web.pam_service, cfg.web.admin_group
            );
            println!(
                "pam:      service file {}, libpam {}",
                if crate::auth::pam_service_file(&cfg.web.pam_service) {
                    "present"
                } else {
                    "MISSING"
                },
                if crate::auth::pam_loaded() {
                    "loaded"
                } else {
                    "unavailable"
                }
            );
            let nft = NftEnforcer::new(
                &cfg.enforcement.table,
                &cfg.enforcement.chain_hook,
                cfg.enforcement.priority,
            );
            println!(
                "nftables: {}",
                if nft.available() {
                    "available"
                } else {
                    "NOT FOUND"
                }
            );
            Some(cfg)
        }
        Err(e) => {
            println!("config:   ERROR: {e}");
            None
        }
    };

    match Db::open(&layout.db) {
        Ok(db) => {
            println!(
                "storage:  {} ({} bytes) · schema v{}",
                layout.db.display(),
                Db::db_size_bytes(&layout.db),
                db.schema_version().unwrap_or(0)
            );
            println!("blocks:   {} active", db.active_block_count().unwrap_or(0));
            println!("detections: {}", db.detection_count().unwrap_or(0));
            println!(
                "log events: {}",
                db.log_event_count(None, None).unwrap_or(0)
            );
            println!(
                "rules:    {} stored · version {}",
                db.list_rules().map(|r| r.len()).unwrap_or(0),
                db.rules_version().unwrap_or(0)
            );
            println!(
                "journal:  cursor {} · status {}",
                db.journal_cursor()
                    .ok()
                    .flatten()
                    .map(|_| "present")
                    .unwrap_or("none"),
                db.log_state("journal.status")
                    .ok()
                    .flatten()
                    .and_then(|v| v.get("state").and_then(|s| s.as_str()).map(str::to_string))
                    .unwrap_or_else(|| "unknown".into())
            );
            println!(
                "geo:      country {} · asn {}",
                if db
                    .get_setting("geo.status")
                    .ok()
                    .flatten()
                    .and_then(|v| v.get("country").cloned())
                    .is_some()
                {
                    "loaded"
                } else {
                    "absent"
                },
                if db
                    .get_setting("geo.status")
                    .ok()
                    .flatten()
                    .and_then(|v| v.get("asn").cloned())
                    .is_some()
                {
                    "loaded"
                } else {
                    "absent"
                }
            );
            println!(
                "alerts:   {} target(s) · {} pending · {} failed",
                db.list_alert_targets().map(|t| t.len()).unwrap_or(0),
                db.alert_stats().map(|s| s.pending).unwrap_or(0),
                db.alert_stats().map(|s| s.failed).unwrap_or(0)
            );
            if let Ok(rows) = db.recent_audit(5) {
                println!("recent audit:");
                for (ts, actor, action, subject) in rows {
                    println!(
                        "  {}  {:<20} {:<24} {}",
                        ts.format("%Y-%m-%d %H:%M:%SZ"),
                        actor,
                        action,
                        subject
                    );
                }
            }
        }
        Err(e) => println!("storage:  ERROR: {e}"),
    }

    if let Some(cfg) = cfg {
        if cfg.geo.enabled {
            println!(
                "geo:      automatic updates enabled ({} h)",
                cfg.geo.update_hours
            );
        }
    }
    Ok(())
}

fn cmd_status(layout: &Layout) -> Result<()> {
    if !layout.has_state() {
        return Err(Error::NotFound(format!(
            "no RustIPS state at {}; run `rustips setup`",
            layout.state_dir.display()
        )));
    }
    let db = Db::open(&layout.db)?;
    let cfg = Config::load(&layout.config).ok();
    let mode = db
        .get_setting("daemon.mode")?
        .and_then(|v| v.as_str().map(str::to_string))
        .or_else(|| cfg.as_ref().map(|c| c.mode.to_string()))
        .unwrap_or_else(|| "unknown".into());

    println!("RustIPS {}", crate::VERSION);
    println!("database: {}", layout.db.display());
    println!("size:     {}", human_bytes(Db::db_size_bytes(&layout.db)));
    println!("mode:     {mode}");

    let active = db.list_active_blocks()?;
    println!("blocks:   {} active", active.len());
    println!("detections: {}", db.detection_count()?);
    println!("strikes:  {}", db.count_strikes()?);
    if let Ok(rules) = db.list_rules() {
        if rules.is_empty() {
            println!("rules:    0 stored (shipped defaults apply)");
        } else {
            println!("rules:    {} stored", rules.len());
        }
    }
    if let Ok(alerts) = db.alert_stats() {
        println!(
            "alerts:   {} pending · {} delivered · {} failed",
            alerts.pending, alerts.delivered, alerts.failed
        );
    }
    if let Ok(targets) = db.list_alert_targets() {
        println!(
            "alert targets: {} ({} enabled)",
            targets.len(),
            targets.iter().filter(|target| target.enabled).count()
        );
    }
    if let Some(status) = db.get_setting("geo.status").ok().flatten() {
        let country = status.get("country").is_some();
        let asn = status.get("asn").is_some();
        println!(
            "geo:      country {}, asn {}",
            if country { "loaded" } else { "absent" },
            if asn { "loaded" } else { "absent" }
        );
    }
    if let Ok(count) = db.log_event_count(None, None) {
        println!("log events: {count}");
    }
    if let Ok(Some(state)) = db.log_state("journal.status") {
        let label = state
            .get("state")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        println!("journal:  {label}");
    }

    let table = cfg
        .map(|c| c.enforcement.table)
        .unwrap_or_else(|| "rustips".into());
    let nft = NftEnforcer::new(&table, "input", -10);
    if nft.available() {
        let present = std::process::Command::new("nft")
            .args(["list", "table", "inet", &table])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        println!(
            "enforcement: nftables inet {table} {}",
            if present { "present" } else { "absent" }
        );
    } else {
        println!("enforcement: nftables not installed");
    }

    if !active.is_empty() {
        println!();
        println!("active blocks:");
        for b in active.iter().take(20) {
            let expiry = match b.expires_at {
                Some(t) => t.format("%Y-%m-%d %H:%M:%SZ").to_string(),
                None => "permanent".to_string(),
            };
            println!(
                "  {:<40} strike {}  until {}  {}",
                b.src, b.strike, expiry, b.reason
            );
        }
    }

    let audit = db.recent_audit(5)?;
    if !audit.is_empty() {
        println!();
        println!("recent activity:");
        for (ts, actor, action, subject) in audit {
            println!(
                "  {}  {:<20} {:<28} {}",
                ts.format("%Y-%m-%d %H:%M:%SZ"),
                actor,
                action,
                subject
            );
        }
    }
    Ok(())
}

fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    format!("{v:.1} {}", UNITS[u])
}

// --------------------------------------------------------------- block management

fn enforcer_for(cfg: &Config) -> Box<dyn Enforcer> {
    Box::new(NftEnforcer::new(
        &cfg.enforcement.table,
        &cfg.enforcement.chain_hook,
        cfg.enforcement.priority,
    ))
}

fn is_allowlisted(db: &Db, ip: IpAddr) -> Result<bool> {
    if net::is_implicitly_allowed(ip) {
        return Ok(true);
    }
    Ok(db.allowlist_matcher()?.iter().any(|c| c.contains(ip)))
}

fn cmd_block(layout: &Layout, ip: &str, duration: &str, reason: &str) -> Result<()> {
    let cfg = Config::load(&layout.config)?;
    let db = Db::open(&layout.db)?;
    let ip = net::parse_ip(ip)?;
    let duration: BlockDuration = duration.parse().map_err(Error::Invalid)?;

    if is_allowlisted(&db, ip)? {
        return Err(Error::Invalid(format!(
            "{ip} is allowlisted; the allowlist has precedence. Remove the entry first."
        )));
    }

    let now = Utc::now();
    let strike = db.strike_count(ip)?;
    let (block, created) = db.upsert_block(ip, duration, strike, reason, None, None, now)?;
    let applied = if cfg.mode == Mode::Enforce {
        let e = enforcer_for(&cfg);
        e.ensure()?;
        e.add(ip)?;
        db.set_enforced(block.id, true)?;
        true
    } else {
        println!("observe mode: block recorded but not applied");
        false
    };
    db.audit(
        &Actor::Cli,
        if created {
            "block.create"
        } else {
            "block.extend"
        },
        &ip.to_string(),
        &format!("manual duration={duration} applied={applied} reason={reason}"),
    )?;
    println!(
        "{} {ip} for {duration}{}",
        if created { "blocked" } else { "extended" },
        if applied { "" } else { " (not enforced)" }
    );
    Ok(())
}

fn cmd_unblock(layout: &Layout, ip: &str) -> Result<()> {
    let cfg = Config::load(&layout.config)?;
    let db = Db::open(&layout.db)?;
    let ip = net::parse_ip(ip)?;

    let Some(block) = db.active_block(ip)? else {
        return Err(Error::NotFound(format!("{ip} is not actively blocked")));
    };

    if cfg.mode == Mode::Enforce {
        let e = enforcer_for(&cfg);
        e.remove(ip)?;
    }
    db.mark_block_state(block.id, BlockState::ManualUnblocked)?;
    if cfg.ladder.unblock_effect == UnblockEffect::Reset {
        db.reset_strike(ip)?;
    }
    db.audit(
        &Actor::Cli,
        "block.manual_unblock",
        &ip.to_string(),
        &format!(
            "strike effect: {}",
            match cfg.ladder.unblock_effect {
                UnblockEffect::Keep => "keep",
                UnblockEffect::Reset => "reset",
            }
        ),
    )?;
    println!("unblocked {ip}");
    Ok(())
}

fn cmd_allow(layout: &Layout, cidr: &str, label: &str, unblock: bool) -> Result<()> {
    let cfg = Config::load(&layout.config)?;
    let db = Db::open(&layout.db)?;
    let cidr = Cidr::parse(cidr).map_err(Error::Invalid)?;
    db.add_allowlist(&cidr, label, false, "cli")?;
    db.audit(&Actor::Cli, "allowlist.add", &cidr.to_string(), label)?;
    println!("allowlisted {cidr}");

    if unblock {
        let mut removed = 0;
        for block in db.list_active_blocks()? {
            if cidr.contains(block.src) {
                if cfg.mode == Mode::Enforce {
                    enforcer_for(&cfg).remove(block.src)?;
                }
                db.mark_block_state(block.id, BlockState::ManualUnblocked)?;
                removed += 1;
            }
        }
        if removed > 0 {
            db.audit(
                &Actor::Cli,
                "block.manual_unblock",
                &cidr.to_string(),
                &format!("{removed} block(s) removed by --unblock"),
            )?;
            println!("removed {removed} existing block(s)");
        }
    }
    Ok(())
}

fn cmd_allowlist(layout: &Layout, json: bool) -> Result<()> {
    let db = Db::open(&layout.db)?;
    let entries = db.list_allowlist()?;
    if json {
        println!("{}", serde_json::to_string_pretty(&entries)?);
        return Ok(());
    }
    println!(
        "{:<24} {:<10} {:<8} CREATED BY",
        "CIDR", "LABEL", "IMPLICIT"
    );
    for e in entries {
        println!(
            "{:<24} {:<10} {:<8} {}",
            e.cidr,
            e.label,
            if e.implicit { "yes" } else { "no" },
            e.created_by
        );
    }
    Ok(())
}

fn cmd_detections(layout: &Layout, limit: u32) -> Result<()> {
    let db = Db::open(&layout.db)?;
    let rows = db.recent_detections(limit)?;
    if rows.is_empty() {
        println!("no detections recorded");
        return Ok(());
    }
    for d in rows {
        println!(
            "{}  {:<8} {:<40} count={}  {}",
            d.first_seen.format("%Y-%m-%d %H:%M:%SZ"),
            d.detector.as_str(),
            d.src,
            d.count,
            d.metadata
        );
    }
    Ok(())
}

// ----------------------------------------------------------------- export/import

#[derive(serde::Serialize, serde::Deserialize)]
struct ExportFile {
    format: String,
    version: u32,
    exported_at: chrono::DateTime<Utc>,
    #[serde(default)]
    blocks: Vec<Block>,
    #[serde(default)]
    strikes: Vec<Strike>,
    #[serde(default)]
    allowlist: Vec<crate::model::AllowlistEntry>,
    #[serde(default)]
    rules: Vec<Rule>,
}

fn cmd_export(layout: &Layout, out: Option<PathBuf>) -> Result<()> {
    let db = Db::open(&layout.db)?;
    let export = ExportFile {
        format: "rustips-export".into(),
        version: 2,
        exported_at: Utc::now(),
        blocks: db.list_active_blocks()?,
        strikes: db.list_strikes()?,
        allowlist: db.list_allowlist()?,
        rules: db.list_rules()?,
    };
    let json = serde_json::to_string_pretty(&export)?;
    match out {
        Some(path) => {
            std::fs::write(&path, json)?;
            println!("wrote {}", path.display());
        }
        None => println!("{json}"),
    }
    Ok(())
}

fn cmd_import(layout: &Layout, file: &Path) -> Result<()> {
    let cfg = Config::load(&layout.config)?;
    let db = Db::open(&layout.db)?;
    let text = std::fs::read_to_string(file)?;
    let value: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| Error::Invalid(format!("{}: {e}", file.display())))?;
    let export: ExportFile = if value.is_array()
        || value.get("format").and_then(|v| v.as_str()) == Some("rustips-rules")
    {
        let rules_value = if value.is_array() {
            value
        } else {
            value
                .get("rules")
                .cloned()
                .ok_or_else(|| Error::Invalid(format!("{}: no `rules` array", file.display())))?
        };
        let rules: Vec<Rule> = serde_json::from_value(rules_value)
            .map_err(|e| Error::Invalid(format!("{}: {e}", file.display())))?;
        ExportFile {
            format: "rustips-rules".into(),
            version: 1,
            exported_at: Utc::now(),
            blocks: Vec::new(),
            strikes: Vec::new(),
            allowlist: Vec::new(),
            rules,
        }
    } else {
        serde_json::from_value(value)
            .map_err(|e| Error::Invalid(format!("{}: {e}", file.display())))?
    };
    if export.format != "rustips-export" && export.format != "rustips-rules" {
        return Err(Error::Invalid(
            "not a RustIPS export or rules document".into(),
        ));
    }

    // Validate the whole rule set before changing anything. Exports from
    // 0.3.0 have no rules; those leave the current rules untouched.
    if !export.rules.is_empty() {
        if let Err(errors) = RuleSet::compile(export.rules.clone(), &cfg.ladder.steps) {
            let detail = errors
                .iter()
                .map(|error| error.to_string())
                .collect::<Vec<_>>()
                .join("; ");
            return Err(Error::Invalid(format!("rule set rejected: {detail}")));
        }
    }

    let now = Utc::now();
    let mut blocks = 0;
    for b in export.blocks {
        let duration = match b.expires_at {
            None => BlockDuration::Permanent,
            Some(t) => BlockDuration::Temporary((t - now).num_seconds().max(1)),
        };
        let _ = db.upsert_block_with_rule(
            b.src, duration, b.strike, &b.reason, b.detector, None, b.rule_id, now,
        )?;
        blocks += 1;
    }
    for s in export.strikes {
        db.set_strike(s.src, s.count, s.last_seen, &s.last_reason)?;
    }
    for a in export.allowlist {
        if a.implicit {
            continue;
        }
        if let Ok(c) = Cidr::parse(&a.cidr) {
            db.add_allowlist(&c, &a.label, false, "import")?;
        }
    }
    let rules = export.rules.len();
    if rules > 0 {
        db.replace_rules(&export.rules, "import", &file.display().to_string())?;
    }

    if cfg.mode == Mode::Enforce {
        let e = enforcer_for(&cfg);
        e.ensure()?;
        let ips: Vec<IpAddr> = db
            .list_active_blocks()?
            .into_iter()
            .map(|b| b.src)
            .collect();
        e.restore(&ips)?;
    }
    db.audit(
        &Actor::Cli,
        "import",
        &file.display().to_string(),
        &format!("{blocks} blocks, {rules} rules"),
    )?;
    println!("imported {blocks} blocks and {rules} rules");
    Ok(())
}

fn cmd_flush(layout: &Layout, yes: bool) -> Result<()> {
    if !yes {
        return Err(Error::Invalid(
            "refusing to flush without --yes: this unblocks every source".into(),
        ));
    }
    let cfg = Config::load(&layout.config)?;
    let db = Db::open(&layout.db)?;
    if cfg.mode == Mode::Enforce {
        let e = enforcer_for(&cfg);
        e.flush()?;
    }
    let n = db.unblock_all()?;
    db.audit(&Actor::Cli, "flush", "", &format!("{n} blocks removed"))?;
    println!(
        "flushed: removed {n} block(s){}",
        if cfg.mode == Mode::Enforce {
            " and the nftables table"
        } else {
            ""
        }
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn install_binary_copies_mode_and_is_idempotent() {
        let dir = std::env::temp_dir().join(format!(
            "rustips-install-bin-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let source = dir.join("source");
        let dest = dir.join("bin/rustips");
        std::fs::write(&source, b"binary").unwrap();
        assert!(install_binary(&source, &dest).unwrap());
        assert_eq!(std::fs::read(&dest).unwrap(), b"binary");
        assert_eq!(
            std::fs::metadata(&dest).unwrap().permissions().mode() & 0o777,
            0o755
        );
        assert!(!install_binary(&dest, &dest).unwrap());
        std::fs::remove_dir_all(dir).ok();
    }
}

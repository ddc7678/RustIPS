//! PAM authentication, group authorisation, break-glass recovery and login
//! throttling (FR-182…FR-183).
//!
//! PAM is loaded with `dlopen` so the binary still starts (in observe mode,
//! with a clear health warning) on a host where libpam is missing. Every call
//! fails closed. The password exists only in the conversation buffer and is
//! zeroed immediately after `pam_end`.

use std::collections::{HashMap, VecDeque};
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};

use crate::error::Result;

const PAM_SUCCESS: c_int = 0;
const PAM_BUF_ERR: c_int = 5;
const PAM_AUTH_ERR: c_int = 7;
const PAM_AUTHINFO_UNAVAIL: c_int = 9;
const PAM_USER_UNKNOWN: c_int = 10;
const PAM_MAXTRIES: c_int = 11;
const PAM_NEW_AUTHTOK_REQD: c_int = 12;
const PAM_ACCT_EXPIRED: c_int = 13;
const PAM_PERM_DENIED: c_int = 6;
const PAM_CONV_ERR: c_int = 19;
const PAM_ABORT: c_int = 26;

const PAM_PROMPT_ECHO_OFF: c_int = 1;
const PAM_PROMPT_ECHO_ON: c_int = 2;

/// Result of one authentication attempt. The distinction is recorded in the
/// audit log; the login page shows it without confirming account existence to
/// anyone who does not know the password (FR-182d).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthOutcome {
    Success,
    BadCredentials,
    /// Correct credentials but the account is locked, expired, or needs a
    /// password change.
    AccountLocked(String),
    /// PAM accepted the credentials but the account is not in the admin group.
    NotAuthorised,
    /// PAM (or its backing store) is unusable. Only break-glass may proceed.
    Unavailable(String),
}

impl AuthOutcome {
    pub fn is_success(&self) -> bool {
        *self == AuthOutcome::Success
    }

    /// Text safe to show to the person logging in.
    pub fn user_message(&self) -> &'static str {
        match self {
            AuthOutcome::Success => "",
            AuthOutcome::BadCredentials => "Invalid credentials.",
            AuthOutcome::AccountLocked(_) => "This account is locked or expired.",
            AuthOutcome::NotAuthorised => {
                "Authenticated, but this account is not in the rustips-admin group."
            }
            AuthOutcome::Unavailable(_) => {
                "PAM authentication is unavailable. Use a break-glass token."
            }
        }
    }

    /// Short machine-readable result for the audit log.
    pub fn audit_result(&self) -> String {
        match self {
            AuthOutcome::Success => "success".into(),
            AuthOutcome::BadCredentials => "bad_credentials".into(),
            AuthOutcome::AccountLocked(reason) => format!("account_locked: {reason}"),
            AuthOutcome::NotAuthorised => "not_authorised".into(),
            AuthOutcome::Unavailable(reason) => format!("pam_unavailable: {reason}"),
        }
    }
}

// ------------------------------------------------------------------- PAM FFI

type PamStartFn =
    unsafe extern "C" fn(*const c_char, *const c_char, *const PamConv, *mut *mut c_void) -> c_int;
type PamAuthFn = unsafe extern "C" fn(*mut c_void, c_int) -> c_int;
type PamStrerrorFn = unsafe extern "C" fn(*mut c_void, c_int) -> *const c_char;
type PamEndFn = unsafe extern "C" fn(*mut c_void, c_int) -> c_int;
type ConvFn = unsafe extern "C" fn(
    c_int,
    *mut *const PamMessage,
    *mut *mut PamResponse,
    *mut c_void,
) -> c_int;

#[repr(C)]
struct PamMessage {
    msg_style: c_int,
    msg: *const c_char,
}

#[repr(C)]
struct PamResponse {
    resp: *mut c_char,
    resp_retcode: c_int,
}

#[repr(C)]
struct PamConv {
    conv: Option<ConvFn>,
    appdata_ptr: *mut c_void,
}

struct PamApi {
    start: PamStartFn,
    authenticate: PamAuthFn,
    acct_mgmt: PamAuthFn,
    strerror: PamStrerrorFn,
    end: PamEndFn,
}

// The function pointers are immutable and safe to call concurrently; PAM
// handles are created per call.
unsafe impl Send for PamApi {}
unsafe impl Sync for PamApi {}

fn pam_api() -> Option<&'static PamApi> {
    static API: OnceLock<Option<PamApi>> = OnceLock::new();
    API.get_or_init(|| unsafe { load_pam() }).as_ref()
}

/// True when libpam could be loaded.
pub fn pam_loaded() -> bool {
    pam_api().is_some()
}

/// The service is only usable if `/etc/pam.d/<name>` exists. Checking first
/// turns a missing service into a clear "unavailable" (break-glass) state
/// instead of a generic credential failure.
pub fn pam_service_file(service: &str) -> bool {
    !service.is_empty()
        && service
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        && Path::new("/etc/pam.d").join(service).is_file()
}

#[allow(clippy::missing_transmute_annotations)]
unsafe fn load_pam() -> Option<PamApi> {
    let handle =
        unsafe { libc::dlopen(c"libpam.so.0".as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    if handle.is_null() {
        return None;
    }
    let symbol = |name: &CStr| unsafe { libc::dlsym(handle, name.as_ptr()) };
    let start = symbol(c"pam_start");
    let authenticate = symbol(c"pam_authenticate");
    let acct_mgmt = symbol(c"pam_acct_mgmt");
    let strerror = symbol(c"pam_strerror");
    let end = symbol(c"pam_end");
    if start.is_null()
        || authenticate.is_null()
        || acct_mgmt.is_null()
        || strerror.is_null()
        || end.is_null()
    {
        return None;
    }
    Some(PamApi {
        start: unsafe { std::mem::transmute(start) },
        authenticate: unsafe { std::mem::transmute(authenticate) },
        acct_mgmt: unsafe { std::mem::transmute(acct_mgmt) },
        strerror: unsafe { std::mem::transmute(strerror) },
        end: unsafe { std::mem::transmute(end) },
    })
}

struct ConvData {
    username: *const c_char,
    password: *const c_char,
}

/// PAM conversation callback. Echo-on prompts (usually the username) get the
/// username; echo-off prompts get the password; informational messages get
/// no response. PAM owns and frees the response array.
unsafe extern "C" fn conversation(
    count: c_int,
    messages: *mut *const PamMessage,
    responses: *mut *mut PamResponse,
    appdata: *mut c_void,
) -> c_int {
    if count <= 0 || messages.is_null() || responses.is_null() || appdata.is_null() {
        return PAM_CONV_ERR;
    }
    let data = unsafe { &*(appdata as *const ConvData) };
    let n = count as usize;
    let array = unsafe { libc::calloc(n, std::mem::size_of::<PamResponse>()) } as *mut PamResponse;
    if array.is_null() {
        return PAM_BUF_ERR;
    }
    for i in 0..n {
        let message = unsafe { *messages.add(i) };
        if message.is_null() {
            continue;
        }
        let style = unsafe { (*message).msg_style };
        let source = match style {
            PAM_PROMPT_ECHO_OFF => data.password,
            PAM_PROMPT_ECHO_ON => data.username,
            _ => std::ptr::null(),
        };
        if source.is_null() {
            continue;
        }
        let copy = unsafe { libc::strdup(source) };
        if copy.is_null() {
            for j in 0..i {
                let resp = unsafe { (*array.add(j)).resp };
                if !resp.is_null() {
                    unsafe { libc::free(resp as *mut c_void) };
                }
            }
            unsafe { libc::free(array as *mut c_void) };
            return PAM_BUF_ERR;
        }
        unsafe { (*array.add(i)).resp = copy };
    }
    unsafe { *responses = array };
    PAM_SUCCESS
}

fn pam_message(api: &PamApi, handle: *mut c_void, code: c_int) -> String {
    if handle.is_null() {
        return format!("PAM error {code}");
    }
    let ptr = unsafe { (api.strerror)(handle, code) };
    if ptr.is_null() {
        return format!("PAM error {code}");
    }
    let text = unsafe { CStr::from_ptr(ptr) }
        .to_string_lossy()
        .into_owned();
    format!("{text} ({code})")
}

fn classify_auth(code: c_int) -> AuthOutcome {
    match code {
        PAM_SUCCESS => AuthOutcome::Success,
        PAM_AUTH_ERR | PAM_USER_UNKNOWN | PAM_PERM_DENIED | PAM_MAXTRIES => {
            AuthOutcome::BadCredentials
        }
        PAM_ACCT_EXPIRED => AuthOutcome::AccountLocked("account expired".into()),
        PAM_NEW_AUTHTOK_REQD => AuthOutcome::AccountLocked("password change required".into()),
        PAM_AUTHINFO_UNAVAIL | PAM_CONV_ERR | PAM_ABORT | 3 | 4 => {
            AuthOutcome::Unavailable(format!("pam_authenticate error {code}"))
        }
        other => AuthOutcome::Unavailable(format!("pam_authenticate error {other}")),
    }
}

/// Authenticate `username` against the PAM service and then require membership
/// of `group`. The password is zeroed before returning.
pub fn authenticate(service: &str, username: &str, password: &str, group: &str) -> AuthOutcome {
    let (Ok(service), Ok(user)) = (CString::new(service), CString::new(username)) else {
        return AuthOutcome::BadCredentials;
    };
    let Ok(secret) = CString::new(password) else {
        return AuthOutcome::BadCredentials;
    };
    let outcome = unsafe { authenticate_inner(&service, &user, secret.as_ptr(), group) };
    // Overwrite the heap buffer, then free it. Do not keep a copy anywhere.
    let mut bytes = secret.into_bytes();
    bytes.fill(0);
    std::hint::black_box(&bytes);
    outcome
}

unsafe fn authenticate_inner(
    service: &CString,
    user: &CString,
    password: *const c_char,
    group: &str,
) -> AuthOutcome {
    let Some(api) = pam_api() else {
        return AuthOutcome::Unavailable("libpam could not be loaded".into());
    };
    if !pam_service_file(service.to_str().unwrap_or("")) {
        return AuthOutcome::Unavailable("the PAM service file is not installed".into());
    }
    let data = ConvData {
        username: user.as_ptr(),
        password,
    };
    let conv = PamConv {
        conv: Some(conversation),
        appdata_ptr: &data as *const ConvData as *mut c_void,
    };
    let mut handle: *mut c_void = std::ptr::null_mut();
    let start = unsafe {
        (api.start)(
            service.as_ptr(),
            user.as_ptr(),
            &conv as *const PamConv,
            &mut handle,
        )
    };
    if start != PAM_SUCCESS || handle.is_null() {
        return AuthOutcome::Unavailable(format!("pam_start error {start}"));
    }

    let auth = unsafe { (api.authenticate)(handle, 0) };
    if auth != PAM_SUCCESS {
        let detail = pam_message(api, handle, auth);
        unsafe { (api.end)(handle, auth) };
        return match classify_auth(auth) {
            AuthOutcome::Unavailable(_) => AuthOutcome::Unavailable(detail),
            other => other,
        };
    }

    // Authentication alone is not enough: expired/locked accounts must be
    // rejected too (FR-182b).
    let acct = unsafe { (api.acct_mgmt)(handle, 0) };
    let end_status = acct;
    unsafe { (api.end)(handle, end_status) };
    if acct != PAM_SUCCESS {
        let detail = format!("pam_acct_mgmt error {acct}");
        return match acct {
            PAM_ACCT_EXPIRED => AuthOutcome::AccountLocked("account expired".into()),
            PAM_NEW_AUTHTOK_REQD => AuthOutcome::AccountLocked("password change required".into()),
            PAM_PERM_DENIED | PAM_AUTH_ERR | PAM_USER_UNKNOWN => AuthOutcome::AccountLocked(detail),
            _ => AuthOutcome::Unavailable(detail),
        };
    }

    if !user_in_group(user.to_str().unwrap_or(""), group) {
        return AuthOutcome::NotAuthorised;
    }
    AuthOutcome::Success
}

/// Re-check an existing session's backing account: PAM account controls plus
/// group membership. PAM failures are fail-closed (FR-182g).
pub fn revalidate(service: &str, username: &str, group: &str) -> bool {
    if !account_valid(service, username) {
        return false;
    }
    user_in_group(username, group)
}

fn account_valid(service: &str, username: &str) -> bool {
    if !pam_service_file(service) {
        return false;
    }
    let (Ok(service), Ok(user)) = (CString::new(service), CString::new(username)) else {
        return false;
    };
    let Some(api) = pam_api() else {
        return false;
    };
    let data = ConvData {
        username: user.as_ptr(),
        password: std::ptr::null(),
    };
    let conv = PamConv {
        conv: Some(conversation),
        appdata_ptr: &data as *const ConvData as *mut c_void,
    };
    let mut handle: *mut c_void = std::ptr::null_mut();
    let start = unsafe {
        (api.start)(
            service.as_ptr(),
            user.as_ptr(),
            &conv as *const PamConv,
            &mut handle,
        )
    };
    if start != PAM_SUCCESS || handle.is_null() {
        return false;
    }
    let rc = unsafe { (api.acct_mgmt)(handle, 0) };
    unsafe { (api.end)(handle, rc) };
    rc == PAM_SUCCESS
}

// --------------------------------------------------------------- NSS / groups

fn passwd_gid(user: &CString) -> Option<libc::gid_t> {
    let mut buf = vec![0 as c_char; 4096];
    loop {
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        let rc = unsafe {
            libc::getpwnam_r(
                user.as_ptr(),
                &mut pwd,
                buf.as_mut_ptr(),
                buf.len(),
                &mut result,
            )
        };
        if rc == 0 && !result.is_null() {
            return Some(pwd.pw_gid);
        }
        if rc == libc::ERANGE && buf.len() < 1 << 20 {
            buf.resize(buf.len() * 2, 0);
            continue;
        }
        return None;
    }
}

fn group_gid(group: &CString) -> Option<libc::gid_t> {
    let mut buf = vec![0 as c_char; 4096];
    loop {
        let mut grp: libc::group = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::group = std::ptr::null_mut();
        let rc = unsafe {
            libc::getgrnam_r(
                group.as_ptr(),
                &mut grp,
                buf.as_mut_ptr(),
                buf.len(),
                &mut result,
            )
        };
        if rc == 0 && !result.is_null() {
            return Some(grp.gr_gid);
        }
        if rc == libc::ERANGE && buf.len() < 1 << 20 {
            buf.resize(buf.len() * 2, 0);
            continue;
        }
        return None;
    }
}

/// Membership of `user` in `group`, resolved through NSS (so SSSD/LDAP groups
/// work). A missing user or group is simply "not a member".
pub fn user_in_group(user: &str, group: &str) -> bool {
    let (Ok(user_c), Ok(group_c)) = (CString::new(user), CString::new(group)) else {
        return false;
    };
    let Some(gid) = group_gid(&group_c) else {
        return false;
    };
    let Some(primary) = passwd_gid(&user_c) else {
        return false;
    };
    let mut ngroups: c_int = 32;
    loop {
        let mut groups = vec![0 as libc::gid_t; ngroups.max(1) as usize];
        let rc = unsafe {
            libc::getgrouplist(user_c.as_ptr(), primary, groups.as_mut_ptr(), &mut ngroups)
        };
        if rc >= 0 {
            return groups
                .get(..ngroups.max(0) as usize)
                .is_some_and(|g| g.contains(&gid));
        }
        if ngroups <= groups.len() as c_int {
            return false;
        }
    }
}

/// Users in the configured admin group, for the "who can log in" view.
pub fn users_in_group(group: &str) -> Vec<String> {
    let Ok(group_c) = CString::new(group) else {
        return Vec::new();
    };
    let Some(gid) = group_gid(&group_c) else {
        return Vec::new();
    };
    let Ok(text) = std::fs::read_to_string("/etc/group") else {
        return Vec::new();
    };
    let mut users = Vec::new();
    for line in text.lines() {
        let mut fields = line.split(':');
        if fields.next() == Some(group) {
            let _passwd = fields.next();
            let _gid = fields.next();
            if let Some(list) = fields.next() {
                for name in list.split(',').filter(|s| !s.is_empty()) {
                    users.push(name.to_string());
                }
            }
        }
    }
    // The primary-group members are not in /etc/group's member list.
    if let Ok(passwd) = std::fs::read_to_string("/etc/passwd") {
        for line in passwd.lines() {
            let mut fields = line.split(':');
            let name = fields.next().unwrap_or("");
            let _pw = fields.next();
            let _uid = fields.next();
            let primary = fields.next().and_then(|s| s.parse::<u32>().ok());
            if primary == Some(gid) && !name.is_empty() && !users.iter().any(|u| u == name) {
                users.push(name.to_string());
            }
        }
    }
    users.sort();
    users.dedup();
    users
}

// ---------------------------------------------------------------- break-glass

#[derive(Debug, Clone, serde::Serialize)]
pub struct Breakglass {
    pub token: String,
    pub expires_at: DateTime<Utc>,
    pub path: PathBuf,
}

fn breakglass_path(state_dir: &Path) -> PathBuf {
    state_dir.join("breakglass")
}

/// Create or renew the one-time root token (FR-182e, FR-216). The file is
/// 0600 inside the 0700 state directory.
pub fn create_breakglass(state_dir: &Path, ttl: Duration) -> Result<Breakglass> {
    std::fs::create_dir_all(state_dir)?;
    let token = random_hex(32)?;
    let expires_at = Utc::now() + chrono::Duration::seconds(ttl.as_secs() as i64);
    let path = breakglass_path(state_dir);
    let body = format!("v1\n{}\n{}\n", expires_at.timestamp_millis(), token);
    let tmp = path.with_extension("tmp");
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(body.as_bytes())?;
    }
    std::fs::rename(&tmp, &path)?;
    crate::paths::set_mode(&path, 0o600)?;
    Ok(Breakglass {
        token,
        expires_at,
        path,
    })
}

/// Verify and consume a break-glass token. Consumed only on success, so a
/// typo does not destroy the recovery path.
pub fn verify_breakglass(state_dir: &Path, candidate: &str) -> bool {
    let path = breakglass_path(state_dir);
    let Ok(text) = std::fs::read_to_string(&path) else {
        return false;
    };
    let mut lines = text.lines();
    if lines.next() != Some("v1") {
        return false;
    }
    let expiry = lines
        .next()
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(i64::MIN);
    let stored = lines.next().unwrap_or("").trim();
    if expiry < Utc::now().timestamp_millis() {
        let _ = std::fs::remove_file(&path);
        return false;
    }
    if !constant_time_eq(stored.as_bytes(), candidate.trim().as_bytes()) {
        return false;
    }
    let _ = std::fs::remove_file(&path);
    true
}

/// Remaining lifetime of the break-glass file, if one exists and is unexpired.
pub fn breakglass_expiry(state_dir: &Path) -> Option<DateTime<Utc>> {
    let text = std::fs::read_to_string(breakglass_path(state_dir)).ok()?;
    let mut lines = text.lines();
    if lines.next() != Some("v1") {
        return None;
    }
    let expiry = lines.next()?.parse::<i64>().ok()?;
    let dt = DateTime::from_timestamp_millis(expiry)?;
    (dt > Utc::now()).then_some(dt)
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

// --------------------------------------------------------------- random tokens

fn fill_random(buf: &mut [u8]) -> Result<()> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = unsafe {
            libc::getrandom(
                buf[filled..].as_mut_ptr() as *mut c_void,
                buf.len() - filled,
                0,
            )
        };
        if n > 0 {
            filled += n as usize;
            continue;
        }
        if n < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        // getrandom(2) missing (pre-3.17) or blocked: fall back to urandom.
        use std::io::Read;
        let mut f = std::fs::File::open("/dev/urandom")?;
        f.read_exact(&mut buf[filled..])?;
        return Ok(());
    }
    Ok(())
}

/// Hex token from the kernel CSPRNG, used for session ids, CSRF tokens and
/// break-glass secrets.
pub fn random_hex(bytes: usize) -> Result<String> {
    let mut buf = vec![0u8; bytes.max(16)];
    fill_random(&mut buf)?;
    let mut out = String::with_capacity(buf.len() * 2);
    for b in buf {
        use std::fmt::Write;
        let _ = write!(out, "{b:02x}");
    }
    Ok(out)
}

// ------------------------------------------------------------- login throttle

const MAX_FAILURES: usize = 5;
const FAILURE_WINDOW: Duration = Duration::from_secs(600);
const LOCKOUT: Duration = Duration::from_secs(900);

#[derive(Default)]
struct Attempts {
    failures: VecDeque<Instant>,
    locked_until: Option<Instant>,
}

/// Per-username and per-source login throttle, in addition to PAM policy
/// (FR-183). In-memory: a restart clears a local lockout, which is acceptable
/// because PAM's own controls remain in force.
#[derive(Default)]
pub struct LoginLimiter {
    inner: Mutex<HashMap<String, Attempts>>,
}

impl LoginLimiter {
    pub fn new() -> LoginLimiter {
        LoginLimiter::default()
    }

    /// Some(remaining) when either key is locked out.
    pub fn locked_for(&self, keys: &[String]) -> Option<Duration> {
        let now = Instant::now();
        let map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let mut worst: Option<Duration> = None;
        for key in keys {
            if let Some(a) = map.get(key)
                && let Some(until) = a.locked_until
                && until > now
            {
                let left = until - now;
                worst = Some(worst.map_or(left, |w: Duration| w.max(left)));
            }
        }
        worst
    }

    pub fn record_failure(&self, keys: &[String]) {
        let now = Instant::now();
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        for key in keys {
            let a = map.entry(key.clone()).or_default();
            while let Some(front) = a.failures.front() {
                if now.duration_since(*front) > FAILURE_WINDOW {
                    a.failures.pop_front();
                } else {
                    break;
                }
            }
            a.failures.push_back(now);
            if a.failures.len() >= MAX_FAILURES {
                a.locked_until = Some(now + LOCKOUT);
                a.failures.clear();
            }
            if a.locked_until.is_some_and(|until| until <= now) {
                a.locked_until = None;
            }
        }
        // Bound the map: only the most recent few hundred keys matter.
        if map.len() > 4096 {
            map.retain(|_, a| {
                a.locked_until.is_some_and(|u| u > now)
                    || a.failures
                        .back()
                        .is_some_and(|t| now.duration_since(*t) < FAILURE_WINDOW)
            });
        }
    }

    pub fn record_success(&self, keys: &[String]) {
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        for key in keys {
            map.remove(key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pam_api_is_optional_but_loadable_here() {
        // Debian has libpam; the test documents that the dynamic loader path
        // works. A host without libpam simply reports false.
        assert!(pam_loaded(), "libpam.so.0 should be loadable");
    }

    #[test]
    fn root_is_in_the_root_group() {
        assert!(user_in_group("root", "root"));
        assert!(!user_in_group("definitely-not-a-user", "root"));
        assert!(!user_in_group("root", "definitely-not-a-group"));
    }

    #[test]
    fn breakglass_roundtrip_is_one_time() {
        let dir = std::env::temp_dir().join(format!(
            "rustips-bg-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let bg = create_breakglass(&dir, Duration::from_secs(60)).unwrap();
        let mode = std::fs::metadata(&bg.path).unwrap().permissions();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(mode.mode() & 0o777, 0o600);
        assert!(!verify_breakglass(&dir, "wrong-token"));
        assert!(bg.path.exists(), "a wrong token must not consume it");
        assert!(verify_breakglass(&dir, &bg.token));
        assert!(!bg.path.exists(), "token is one-time");
        assert!(!verify_breakglass(&dir, &bg.token));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn expired_breakglass_is_refused() {
        let dir = std::env::temp_dir().join(format!(
            "rustips-bg-exp-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = breakglass_path(&dir);
        std::fs::write(
            &path,
            format!("v1\n{}\nabc\n", Utc::now().timestamp_millis() - 1000),
        )
        .unwrap();
        assert!(!verify_breakglass(&dir, "abc"));
        assert!(!path.exists(), "expired token is cleaned up");
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn limiter_locks_and_clears() {
        let limiter = LoginLimiter::new();
        let keys = vec!["user:alice".to_string(), "ip:203.0.113.7".to_string()];
        for _ in 0..MAX_FAILURES - 1 {
            limiter.record_failure(&keys);
            assert!(limiter.locked_for(&keys).is_none());
        }
        limiter.record_failure(&keys);
        assert!(limiter.locked_for(&keys).is_some());
        limiter.record_success(&keys);
        assert!(limiter.locked_for(&keys).is_none());
    }

    #[test]
    fn tokens_are_random_and_hex() {
        let a = random_hex(16).unwrap();
        let b = random_hex(16).unwrap();
        assert_eq!(a.len(), 32);
        assert_ne!(a, b);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn missing_service_fails_closed() {
        let outcome = authenticate("definitely-not-a-rustips-service", "root", "x", "root");
        assert!(
            matches!(outcome, AuthOutcome::Unavailable(_)),
            "{outcome:?}"
        );
    }
}

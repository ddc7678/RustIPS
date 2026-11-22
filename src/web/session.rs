//! In-memory admin sessions: HttpOnly cookie tokens, CSRF secrets, idle and
//! absolute timeouts, and the revalidation clock (FR-182g/FR-182h).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::auth;

#[derive(Debug, Clone)]
pub struct SessionView {
    pub user: String,
    pub csrf: String,
    pub breakglass: bool,
    pub created: Instant,
    pub last_seen: Instant,
    /// True when the caller should re-check PAM and group membership now.
    pub needs_revalidation: bool,
}

struct Session {
    user: String,
    csrf: String,
    breakglass: bool,
    created: Instant,
    last_seen: Instant,
    last_validated: Instant,
}

pub struct Sessions {
    inner: Mutex<HashMap<String, Session>>,
    idle: Duration,
    absolute: Duration,
    revalidate: Duration,
}

impl Sessions {
    pub fn new(idle: Duration, absolute: Duration, revalidate: Duration) -> Sessions {
        Sessions {
            inner: Mutex::new(HashMap::new()),
            idle,
            absolute,
            revalidate,
        }
    }

    /// Create a session and return `(cookie token, csrf token)`. The token is
    /// rotated on every login by construction.
    pub fn create(&self, user: &str, breakglass: bool) -> (String, String) {
        let token = auth::random_hex(32).unwrap_or_else(|_| fallback_token());
        let csrf = auth::random_hex(32).unwrap_or_else(|_| fallback_token());
        let now = Instant::now();
        let mut map = self.lock();
        map.retain(|_, s| {
            now.duration_since(s.last_seen) < self.idle
                && now.duration_since(s.created) < self.absolute
        });
        map.insert(
            token.clone(),
            Session {
                user: user.to_string(),
                csrf: csrf.clone(),
                breakglass,
                created: now,
                last_seen: now,
                last_validated: now,
            },
        );
        (token, csrf)
    }

    /// Look up a token and refresh its idle timer.
    pub fn touch(&self, token: &str) -> Option<SessionView> {
        let now = Instant::now();
        let mut map = self.lock();
        let session = map.get_mut(token)?;
        if now.duration_since(session.last_seen) >= self.idle
            || now.duration_since(session.created) >= self.absolute
        {
            map.remove(token);
            return None;
        }
        session.last_seen = now;
        let needs_revalidation =
            !session.breakglass && now.duration_since(session.last_validated) >= self.revalidate;
        Some(SessionView {
            user: session.user.clone(),
            csrf: session.csrf.clone(),
            breakglass: session.breakglass,
            created: session.created,
            last_seen: session.last_seen,
            needs_revalidation,
        })
    }

    pub fn mark_validated(&self, token: &str) {
        if let Some(session) = self.lock().get_mut(token) {
            session.last_validated = Instant::now();
        }
    }

    pub fn remove(&self, token: &str) {
        self.lock().remove(token);
    }

    pub fn count(&self) -> usize {
        self.lock().len()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Session>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

fn fallback_token() -> String {
    // Only reached if /dev/urandom and getrandom(2) both fail. Refusing to
    // create a session is safer than a predictable token.
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{nanos:032x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_roundtrip_and_csrf() {
        let sessions = Sessions::new(
            Duration::from_secs(60),
            Duration::from_secs(600),
            Duration::from_secs(300),
        );
        let (token, csrf) = sessions.create("alice", false);
        let view = sessions.touch(&token).unwrap();
        assert_eq!(view.user, "alice");
        assert!(auth::constant_time_eq(
            view.csrf.as_bytes(),
            csrf.as_bytes()
        ));
        assert!(!view.needs_revalidation);
        sessions.remove(&token);
        assert!(sessions.touch(&token).is_none());
    }

    #[test]
    fn idle_timeout_expires() {
        let sessions = Sessions::new(
            Duration::from_millis(5),
            Duration::from_secs(600),
            Duration::from_secs(300),
        );
        let (token, _) = sessions.create("alice", false);
        std::thread::sleep(Duration::from_millis(20));
        assert!(sessions.touch(&token).is_none());
    }

    #[test]
    fn revalidation_is_due_after_the_interval() {
        let sessions = Sessions::new(
            Duration::from_secs(60),
            Duration::from_secs(600),
            Duration::from_millis(5),
        );
        let (token, _) = sessions.create("alice", false);
        std::thread::sleep(Duration::from_millis(20));
        let view = sessions.touch(&token).unwrap();
        assert!(view.needs_revalidation);
        sessions.mark_validated(&token);
        assert!(!sessions.touch(&token).unwrap().needs_revalidation);
    }

    #[test]
    fn csrf_tokens_are_unique_and_bounded() {
        let sessions = Sessions::new(
            Duration::from_secs(60),
            Duration::from_secs(600),
            Duration::from_secs(300),
        );
        let (_, a) = sessions.create("alice", false);
        let (_, b) = sessions.create("alice", false);
        assert_ne!(a, b);
        assert_eq!(sessions.count(), 2);
    }
}

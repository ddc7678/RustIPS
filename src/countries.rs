//! Custom country-badge colors for the web UI.
//!
//! The default badge uses the same blue accent as detector tags. Administrators
//! can override the background and text color for one or more ISO country
//! codes from Settings. Colors are stored in SQLite and emitted as a small
//! generated stylesheet so the strict CSP can keep forbidding inline styles.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::db::Db;
use crate::error::Result;

pub const SETTING_KEY: &str = "geo.country_colors";
pub const DEFAULT_SETTING_KEY: &str = "geo.country_default";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CountryColor {
    pub background: String,
    pub foreground: String,
}

pub type CountryColors = BTreeMap<String, CountryColor>;

pub fn default_color() -> CountryColor {
    CountryColor {
        background: "#000000".into(),
        foreground: "#ffffff".into(),
    }
}

pub fn load_default(db: &Db) -> CountryColor {
    db.get_setting(DEFAULT_SETTING_KEY)
        .ok()
        .flatten()
        .and_then(|value| serde_json::from_value::<CountryColor>(value).ok())
        .filter(|color| {
            normalize_color(&color.background).is_some()
                && normalize_color(&color.foreground).is_some()
        })
        .unwrap_or_else(default_color)
}

pub fn save_default(db: &Db, color: &CountryColor) -> Result<()> {
    let background = normalize_color(&color.background).unwrap_or_else(|| "#000000".into());
    let foreground = normalize_color(&color.foreground).unwrap_or_else(|| "#ffffff".into());
    db.set_setting(
        DEFAULT_SETTING_KEY,
        &serde_json::to_value(CountryColor {
            background,
            foreground,
        })?,
    )
}

pub fn load(db: &Db) -> CountryColors {
    db.get_setting(SETTING_KEY)
        .ok()
        .flatten()
        .and_then(|value| serde_json::from_value(value).ok())
        .unwrap_or_default()
}

pub fn save(db: &Db, colors: &CountryColors) -> Result<()> {
    if colors.is_empty() {
        db.delete_setting(SETTING_KEY)
    } else {
        db.set_setting(SETTING_KEY, &serde_json::to_value(colors)?)
    }
}

/// Normalise an ISO 3166-1 alpha-2 country code.
pub fn normalize_codes(raw: &str) -> Option<Vec<String>> {
    let mut codes = Vec::new();
    for part in raw.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let code = normalize_code(part)?;
        if !codes.contains(&code) {
            codes.push(code);
        }
    }
    if codes.is_empty() { None } else { Some(codes) }
}

pub fn normalize_code(raw: &str) -> Option<String> {
    let code = raw.trim().to_ascii_uppercase();
    if code.len() == 2 && code.chars().all(|c| c.is_ascii_uppercase()) {
        Some(code)
    } else {
        None
    }
}

/// Accept `#rrggbb` only; this is what the Settings color picker submits.
pub fn normalize_color(raw: &str) -> Option<String> {
    let color = raw.trim().to_ascii_lowercase();
    if color.len() == 7
        && color.starts_with('#')
        && color[1..].chars().all(|c| c.is_ascii_hexdigit())
    {
        Some(color)
    } else {
        None
    }
}

pub fn css(colors: &CountryColors, default: &CountryColor) -> String {
    let default_background =
        normalize_color(&default.background).unwrap_or_else(|| "#000000".into());
    let default_foreground =
        normalize_color(&default.foreground).unwrap_or_else(|| "#ffffff".into());
    let mut out = format!(
        "/* generated from settings.geo.country_colors */\n.country-tag {{ background: {default_background}; color: {default_foreground}; }}\n"
    );
    for (code, color) in colors {
        let Some(code) = normalize_code(code) else {
            continue;
        };
        let (Some(background), Some(foreground)) = (
            normalize_color(&color.background),
            normalize_color(&color.foreground),
        ) else {
            continue;
        };
        out.push_str(&format!(
            ".country-{code} {{ background: {background}; color: {foreground}; }}\n"
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_codes_and_colors() {
        assert_eq!(normalize_code(" cn ").as_deref(), Some("CN"));
        assert_eq!(normalize_code("USA"), None);
        assert_eq!(normalize_code("1A"), None);
        assert_eq!(normalize_color("#B91C1C").as_deref(), Some("#b91c1c"));
        assert_eq!(normalize_color("red"), None);
        assert_eq!(normalize_color("#12345"), None);
        assert_eq!(
            normalize_codes(" CN, ru, CN ,, us ").unwrap(),
            vec!["CN", "RU", "US"]
        );
        assert!(normalize_codes("CN, USA").is_none());
    }

    #[test]
    fn css_is_deterministic_and_drops_invalid_entries() {
        let mut colors = CountryColors::new();
        colors.insert(
            "CN".into(),
            CountryColor {
                background: "#B91C1C".into(),
                foreground: "#FFFFFF".into(),
            },
        );
        colors.insert(
            "bad".into(),
            CountryColor {
                background: "#000000".into(),
                foreground: "#ffffff".into(),
            },
        );
        let css = css(&colors, &default_color());
        assert!(css.contains(".country-tag { background: #000000; color: #ffffff; }"));
        assert!(css.contains(".country-CN { background: #b91c1c; color: #ffffff; }"));
        assert!(!css.contains(".country-bad"));
    }
}

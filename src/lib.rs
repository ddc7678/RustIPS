//! RustIPS library root. The binary is a thin wrapper around [`cli`].

pub mod alerts;
pub mod auth;
pub mod capture;
pub mod cli;
pub mod config;
pub mod daemon;
pub mod db;
pub mod decode;
pub mod detect;
pub mod enforce;
pub mod error;
pub mod geo;
pub mod logs;
pub mod model;
pub mod net;
pub mod params;
pub mod paths;
pub mod rules;
pub mod system;
pub mod web;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

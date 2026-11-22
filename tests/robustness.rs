//! Fuzz-like robustness tests: deterministic random inputs must never panic
//! and every parser must keep its output bounded.

use rustips::decode::{LinkType, decode};
use rustips::logs::parse::{event_from_record, journal_record, sanitize_message};

fn next(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    *state
}

#[test]
fn decoders_never_panic_on_random_input() {
    let mut state = 0x1234_5678_9abc_def0u64;
    for i in 0..5_000 {
        let len = (next(&mut state) % 600) as usize;
        let mut bytes = vec![0u8; len];
        for byte in &mut bytes {
            *byte = (next(&mut state) >> 17) as u8;
        }
        let link = match i % 4 {
            0 => LinkType::Ethernet,
            1 => LinkType::RawIp,
            2 => LinkType::LinuxSll,
            _ => LinkType::Null,
        };
        if let Some(pkt) = decode(link, &bytes) {
            assert!(pkt.payload_len <= bytes.len());
            assert!(pkt.payload.len() <= bytes.len());
        }
    }
}

#[test]
fn journal_parser_never_panics_on_random_bytes() {
    let mut state = 0xfeed_face_dead_beefu64;
    for _ in 0..5_000 {
        let len = (next(&mut state) % 800) as usize;
        let mut bytes = vec![0u8; len];
        for byte in &mut bytes {
            *byte = (next(&mut state) >> 13) as u8;
        }
        if let Some(record) = journal_record(&bytes) {
            let event = event_from_record(&record, 256, &["secret".to_string()]);
            assert!(event.message.len() <= 256);
        }
    }
}

#[test]
fn message_sanitizer_keeps_bounds_and_controls() {
    let mut state = 0x0bad_c0de_1234_5678u64;
    for _ in 0..5_000 {
        let len = (next(&mut state) % 400) as usize;
        let mut text = String::with_capacity(len);
        for _ in 0..len {
            let code = (next(&mut state) % 0x2FF) as u32;
            if let Some(ch) = char::from_u32(code) {
                text.push(ch);
            }
        }
        let max = (next(&mut state) % 200) as usize;
        let out = sanitize_message(&text, max, &["password".to_string()]);
        assert!(out.len() <= max || max == 0);
        assert!(!out.chars().any(|c| c.is_control()));
    }
}

#!/usr/bin/env python3
"""Receive RustIPS webhook alerts and forward them as e-mail.

This is the documented bridge from FR-204b: RustIPS only speaks a generic JSON
webhook; the administrator can run this small service next to it when SMTP is
wanted. It has no dependency outside the Python 3 standard library.

Environment:
  RUSTIPS_BRIDGE_LISTEN   listen address (default 127.0.0.1:9090)
  RUSTIPS_EMAIL_TO        recipient (required unless --dry-run)
  RUSTIPS_EMAIL_FROM      sender (default rustips@<hostname>)
  RUSTIPS_SMTP_HOST       SMTP host (if unset, use RUSTIPS_SENDMAIL)
  RUSTIPS_SMTP_PORT       SMTP port (default 587)
  RUSTIPS_SMTP_USER       SMTP username (optional)
  RUSTIPS_SMTP_PASS       SMTP password (optional; use an environment file)
  RUSTIPS_SMTP_STARTTLS   "1" (default) or "0"
  RUSTIPS_SENDMAIL        local sendmail path (default /usr/sbin/sendmail -t)

Examples:
  RUSTIPS_EMAIL_TO=admin@example.net RUSTIPS_SMTP_HOST=mail.example.net \
    ./scripts/webhook-email-bridge.py
  ./scripts/webhook-email-bridge.py --self-test
  ./scripts/webhook-email-bridge.py --dry-run --once
"""

from __future__ import annotations

import argparse
import json
import os
import smtplib
import subprocess
import sys
from email.message import EmailMessage
from http.server import BaseHTTPRequestHandler, HTTPServer

MAX_BODY = 64 * 1024


def format_message(payload: dict) -> tuple[str, str]:
    event = payload.get("event", "alert")
    if event == "operational":
        subject = f"[RustIPS] operational: {payload.get('kind', 'unknown')}"
        body = f"{payload.get('message', '')}\n\n{json.dumps(payload, indent=2, sort_keys=True)}\n"
        return subject, body
    detector = payload.get("detector", "?")
    src = payload.get("src", "?")
    action = payload.get("action", "?")
    severity = payload.get("severity", "?")
    subject = f"[RustIPS] {detector} {src} ({action})"
    lines = [
        f"Detector: {detector} ({payload.get('detector_title', '')})",
        f"Severity: {severity}",
        f"Source:   {src}",
        f"Destination: {payload.get('dst', '-')}:{payload.get('dst_port', '-')}",
        f"Action:   {action}",
        f"Count:    {payload.get('count', '?')} in {payload.get('window_secs', '?')}s",
        f"Rule:     {payload.get('rule_id', '-')} {payload.get('rule_name', '')}",
        f"Country/ASN: {payload.get('country', '-')} / {payload.get('asn', '-')}",
        f"First/last: {payload.get('first_seen', '-')} / {payload.get('last_seen', '-')}",
        "",
        json.dumps(payload, indent=2, sort_keys=True),
        "",
    ]
    return subject, "\n".join(lines)


def build_email(payload: dict) -> EmailMessage:
    subject, body = format_message(payload)
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = os.environ.get("RUSTIPS_EMAIL_FROM", "rustips@localhost")
    msg["To"] = os.environ.get("RUSTIPS_EMAIL_TO", "")
    msg.set_content(body)
    return msg


def send_email(msg: EmailMessage, dry_run: bool) -> None:
    if dry_run:
        print(f"--- dry run ---\nTo: {msg['To']}\nSubject: {msg['Subject']}\n\n{msg.get_content()}")
        return
    if not msg["To"]:
        raise RuntimeError("RUSTIPS_EMAIL_TO is required")
    host = os.environ.get("RUSTIPS_SMTP_HOST")
    if host:
        port = int(os.environ.get("RUSTIPS_SMTP_PORT", "587"))
        user = os.environ.get("RUSTIPS_SMTP_USER")
        password = os.environ.get("RUSTIPS_SMTP_PASS")
        starttls = os.environ.get("RUSTIPS_SMTP_STARTTLS", "1") != "0"
        with smtplib.SMTP(host, port, timeout=20) as smtp:
            if starttls:
                smtp.starttls()
            if user:
                smtp.login(user, password or "")
            smtp.send_message(msg)
        return
    sendmail = os.environ.get("RUSTIPS_SENDMAIL", "/usr/sbin/sendmail")
    subprocess.run([sendmail, "-t"], input=msg.as_bytes(), check=True)


class Handler(BaseHTTPRequestHandler):
    dry_run = False
    once = False
    server_ref: HTTPServer | None = None

    def log_message(self, *_args) -> None:  # keep the bridge quiet
        pass

    def do_POST(self) -> None:  # noqa: N802
        if self.path.rstrip("/") not in ("/hook", ""):
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", "0"))
        if length > MAX_BODY:
            self.send_error(413)
            return
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self.send_error(400, "invalid JSON")
            return
        try:
            send_email(build_email(payload), self.dry_run)
        except Exception as error:  # report, but keep the service up
            print(f"bridge delivery failed: {error}", file=sys.stderr)
            self.send_error(502, "delivery failed")
            return
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()
        if self.once and self.server_ref is not None:
            # Stop after this request so the command can be used in tests.
            self.server_ref.shutdown()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="print instead of sending")
    parser.add_argument("--once", action="store_true", help="handle one request and exit")
    parser.add_argument("--self-test", action="store_true", help="format a sample alert and exit")
    args = parser.parse_args()

    if args.self_test:
        sample = {
            "event": "detection",
            "detector": "DET-12",
            "detector_title": "HTTP known-bad path probe",
            "severity": "warning",
            "src": "203.0.113.50",
            "dst": "192.0.2.10",
            "dst_port": 80,
            "count": 1,
            "window_secs": 1,
            "action": "blocked",
            "rule_id": 6,
            "rule_name": "HTTP detectors escalate",
            "country": "CN",
            "asn": 64500,
        }
        subject, body = format_message(sample)
        print(f"Subject: {subject}\n\n{body}")
        return 0

    listen = os.environ.get("RUSTIPS_BRIDGE_LISTEN", "127.0.0.1:9090")
    host, _, port = listen.rpartition(":")
    if not host:
        host = "127.0.0.1"
    server = HTTPServer((host, int(port)), Handler)
    Handler.dry_run = args.dry_run
    Handler.once = args.once
    Handler.server_ref = server
    print(f"listening on http://{host}:{port}/hook (dry_run={args.dry_run})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

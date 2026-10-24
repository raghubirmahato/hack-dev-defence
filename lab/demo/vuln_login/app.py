#!/usr/bin/env python3
"""Deliberately vulnerable login app for HDD HK1 demo rehearsals.

WARNING: THIS APPLICATION IS INTENTIONALLY VULNERABLE. ITS ONLY PURPOSE IS TO
GIVE THE HK1 DEMO A LOCAL "WITHOUT HDD" TARGET. The login query is built by
string concatenation on purpose, so the six mandated SQL-injection payloads and
the auth-bypass forms in ``lab/demo/payloads.tsv`` reach a real SQL engine.

Rules for this file (lab only, never shipped):
  * standard library only (http.server, sqlite3, secrets, ...): no pip install;
  * loopback only, hard-coded default 127.0.0.1:8081 and a hard refusal of any
    non-loopback bind address: this app must never be exposed beyond the machine;
  * the query is really executed by SQLite. There is no query evaluator here and
    no payload special-casing: the vulnerability is the missing parameterisation;
  * seed users are created at start with random passwords printed once to the
    console (there is no hardcoded default password and no password file);
  * the app is not part of any shipped binary or Cargo graph (it lives under
    ``lab/``, which is lab-only by repository rule).

Expected direct (no HDD) behaviour is recorded in ``lab/demo/vuln_login/README.md``
and was verified against this SQLite app: 8 of the 12 demo payloads reach the admin
page directly. M1, M2, M3, M5, M6 and the auth-bypass forms B1, B2, B6 bypass the
login. M4 ``admin' #`` and B4 ``' or 1=1#`` are SQL errors because SQLite has no
``#`` comment syntax; B3 carries parentheses this query shape does not have; B5 runs
but matches no row. SQLite treats an unterminated ``/*`` as a comment to the end of
the input, which is why M5/B6 do bypass this app. The remaining payloads are still
sent, and HDD must block all twelve by intent. docs/SPEC.md E1.1 and P28 record that
some mandated payloads are dialect-invalid on a given endpoint: that is expected and
documented here rather than hidden.
"""

from __future__ import annotations

import argparse
import html
import ipaddress
import os
import secrets
import sqlite3
import sys
import threading
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HOST_DEFAULT = "127.0.0.1"
PORT_DEFAULT = 8081
SESSION_COOKIE = "vuln_login_session"
MAX_BODY_BYTES = 64 * 1024

# Username and role of the fake accounts. Passwords are generated per run.
SEED_USERS = (
    ("admin", "admin"),
    ("demo", "user"),
    ("auditor", "user"),
)

BANNER = """
================================================================================
  HDD HK1 LAB APP - INTENTIONALLY VULNERABLE - NEVER EXPOSE BEYOND LOOPBACK
  The login query is built by string concatenation on purpose (SQL injection).
  Fake users only. Random passwords, printed once below. Not a product, not
  protected, lab/rehearsal only. See lab/demo/vuln_login/README.md.
================================================================================
"""


def log(message: str) -> None:
    """Print one prefixed console line (flushed so the dev launcher sees it live)."""
    print("[vuln-login] " + message, flush=True)


def one_line(text: str) -> str:
    """Collapse control characters so a logged query stays a single console line."""
    return " ".join(text.split())


def page(title: str, body: str, marker: str) -> str:
    """Render one small self-contained HTML page (inline CSS, no external requests)."""
    return (
        "<!doctype html>\n"
        '<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>{html.escape(title)}</title>"
        "<style>"
        "body{font:16px/1.5 system-ui,sans-serif;max-width:720px;margin:3rem auto;padding:0 1rem;color:#15181d;background:#f6f7f9}"
        "h1{font-size:1.5rem}form{display:grid;gap:.6rem;max-width:20rem;margin-top:1rem}"
        "label{font-weight:600}input{padding:.5rem;font:inherit;border:1px solid #8886;border-radius:6px}"
        "button{padding:.5rem .9rem;font:inherit;border:0;border-radius:6px;background:#b3261e;color:#fff;cursor:pointer}"
        ".err{color:#b3261e;font-weight:600}.mu{color:#5a6472}table{border-collapse:collapse;margin-top:1rem}"
        "td,th{text-align:left;padding:.35rem .7rem;border-bottom:1px solid #8884}"
        "code{background:#e8ebf0;padding:.1rem .3rem;border-radius:4px}"
        "</style></head><body>"
        f'<div data-page="{marker}">'
        f"{body}"
        "</div>"
        '<p class="mu"><small>LAB DEMO APP - intentionally vulnerable - never exposed beyond loopback.</small></p>'
        "</body></html>\n"
    )


def login_page(message: str = "", marker: str = "login") -> str:
    """The login form page (no admin markers: the attack script classifies on them)."""
    note = f'<p class="err">{html.escape(message)}</p>' if message else ""
    return page(
        "Sign in",
        "<h1>Staff sign-in</h1>"
        "<p>Please sign in to continue.</p>"
        f"{note}"
        '<form method="post" action="/login">'
        '<label for="username">Username</label>'
        '<input id="username" name="username" autocomplete="username" required>'
        '<label for="password">Password</label>'
        '<input id="password" name="password" type="password" autocomplete="current-password" required>'
        "<button type=\"submit\">Sign in</button>"
        "</form>",
        marker,
    )


def admin_page(username: str, role: str, users: list[tuple[int, str, str]]) -> str:
    """The page behind the login. ``Admin panel``/``data-page="admin"`` are the markers."""
    rows = "".join(
        f"<tr><td>{user_id}</td><td>{html.escape(name)}</td><td>{html.escape(user_role)}</td></tr>"
        for user_id, name, user_role in users
    )
    return page(
        "Admin panel",
        "<h1>Admin panel</h1>"
        f"<p>Signed in as <strong>{html.escape(username)}</strong> (role: {html.escape(role)}).</p>"
        "<p>You are authenticated. In the demo this page opening means the login was bypassed</p>"
        "<table><thead><tr><th>id</th><th>username</th><th>role</th></tr></thead>"
        f"<tbody>{rows}</tbody></table>"
        '<form method="post" action="/logout"><button type="submit">Sign out</button></form>',
        "admin",
    )


def error_page(code: int, title: str, detail: str) -> str:
    """A 4xx/5xx page that shows the raw SQL error (typical of a vulnerable dev app)."""
    return page(
        title,
        f"<h1>{html.escape(title)}</h1><p>{html.escape(detail)}</p>",
        "error-page",
    )


class AppState:
    """Process-wide state: one SQLite connection, one lock, in-memory sessions."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        # check_same_thread=False is safe here because every use is under self.lock.
        self.conn = sqlite3.connect(":memory:", check_same_thread=False)
        self.conn.execute(
            "CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "username TEXT NOT NULL, password TEXT NOT NULL, role TEXT NOT NULL)"
        )
        self.credentials: list[tuple[str, str, str]] = []
        for username, role in SEED_USERS:
            password = secrets.token_urlsafe(12)
            self.conn.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                (username, password, role),
            )
            self.credentials.append((username, password, role))
        self.conn.commit()
        self.sessions: dict[str, str] = {}

    def attempt_login(
        self, username: str, password: str
    ) -> tuple[tuple[str, str, str] | None, str, str | None]:
        """Run the deliberately vulnerable login query.

        Returns ``((session_token, username, role) | None, sql, sql_error)``.
        The SQL is real string concatenation: this is the vulnerability the demo
        is about. Do not "fix" it; that would remove the reason for this file.
        """
        sql = (
            "SELECT id, username, role FROM users "
            "WHERE username='%s' AND password='%s'" % (username, password)
        )
        with self.lock:
            try:
                rows = self.conn.execute(sql).fetchall()
            except sqlite3.Error as exc:
                return None, sql, f"{type(exc).__name__}: {exc}"
            if not rows:
                return None, sql, None
            # A successful row (the first by rowid order) is the session identity.
            _user_id, name, role = rows[0]
            token = secrets.token_hex(24)
            self.sessions[token] = name
            return (token, name, role), sql, None

    def session_user(self, token: str) -> str | None:
        with self.lock:
            return self.sessions.get(token)

    def drop_session(self, token: str) -> None:
        with self.lock:
            self.sessions.pop(token, None)

    def list_users(self) -> list[tuple[int, str, str]]:
        with self.lock:
            return self.conn.execute(
                "SELECT id, username, role FROM users ORDER BY id"
            ).fetchall()


STATE = AppState()


class Handler(BaseHTTPRequestHandler):
    """Tiny HTTP handler: /login (form and GET), /admin, /logout, /healthz, /."""

    server_version = "HDD-lab-vuln-login/1.0"

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - stdlib signature
        """Silence the stdlib access log; every interesting line goes through log()."""

    def log_error(self, format: str, *args: object) -> None:  # noqa: A002 - stdlib signature
        log("request error: " + one_line(format % args))

    # -- response helpers -------------------------------------------------
    def _send(
        self,
        status: int,
        body: str,
        *,
        content_type: str = "text/html; charset=utf-8",
        headers: dict[str, str] | None = None,
    ) -> None:
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Lab-Only", "intentionally-vulnerable")
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(encoded)

    def _redirect(self, location: str, *, cookie: str | None = None) -> None:
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        if cookie is not None:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()

    def _session_token(self) -> str:
        raw = self.headers.get("Cookie", "")
        cookie = SimpleCookie()
        try:
            cookie.load(raw)
        except Exception:  # malformed Cookie header: treat as anonymous
            return ""
        morsel = cookie.get(SESSION_COOKIE)
        return morsel.value if morsel is not None else ""

    # -- routing ----------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802 - stdlib naming
        try:
            self._handle("GET")
        except (BrokenPipeError, ConnectionResetError):
            return

    def do_POST(self) -> None:  # noqa: N802 - stdlib naming
        try:
            self._handle("POST")
        except (BrokenPipeError, ConnectionResetError):
            return

    def _handle(self, method: str) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"

        if path == "/healthz" and method == "GET":
            self._send(HTTPStatus.OK, "ok\n", content_type="text/plain; charset=utf-8")
            return
        if path == "/" and method == "GET":
            self._redirect("/login")
            return
        if path == "/login" and method == "GET":
            query = parse_qs(parsed.query, keep_blank_values=True)
            # The query-string login attempt exists in this lab app so the GET
            # vector of the attack script exercises real server-side SQL too
            # (the live target may or may not accept it; the script sends both).
            if "username" in query or "password" in query:
                self._login(
                    method,
                    query.get("username", [""])[0],
                    query.get("password", [""])[0],
                )
                return
            self._send(HTTPStatus.OK, login_page())
            return
        if path == "/login" and method == "POST":
            self._read_form_login()
            return
        if path == "/admin" and method == "GET":
            token = self._session_token()
            username = STATE.session_user(token) if token else None
            if username is None:
                self._redirect("/login?next=%2Fadmin")
                return
            users = STATE.list_users()
            role = next((r for _i, n, r in users if n == username), "user")
            self._send(HTTPStatus.OK, admin_page(username, role, users))
            return
        if path == "/logout" and method in ("GET", "POST"):
            token = self._session_token()
            if token:
                STATE.drop_session(token)
            expired = f"{SESSION_COOKIE}=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax"
            self._redirect("/login", cookie=expired)
            return
        self._send(
            HTTPStatus.NOT_FOUND,
            error_page(404, "Not found", f"No page at {parsed.path}"),
        )

    def _read_form_login(self) -> None:
        content_type = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if content_type not in ("", "application/x-www-form-urlencoded"):
            self._send(
                HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                error_page(415, "Unsupported media type", "Send an urlencoded login form."),
            )
            return
        try:
            length = int(self.headers.get("Content-Length") or "0")
        except ValueError:
            length = -1
        if length < 0 or length > MAX_BODY_BYTES:
            self._send(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                error_page(413, "Bad request body", "Login bodies are capped at 64 KiB here."),
            )
            return
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        form = parse_qs(raw, keep_blank_values=True)
        self._login(
            "POST", form.get("username", [""])[0], form.get("password", [""])[0]
        )

    def _login(self, method: str, username: str, password: str) -> None:
        log(
            f"{method} /login attempt: username={one_line(username)!r} "
            f"password={one_line(password)!r}"
        )
        result, sql, sql_error = STATE.attempt_login(username, password)
        # Log the real query: it makes the rehearsal honest and debuggable.
        log("SQL executed: " + one_line(sql))
        if sql_error is not None:
            log("query failed (dialect/syntax): " + one_line(sql_error))
            self._send(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                error_page(
                    500,
                    "SQL error",
                    "The login query raised: " + sql_error
                    + " (some injection payloads are dialect-specific).",
                ),
            )
            return
        if result is None:
            log("result: rejected (401)")
            self._send(HTTPStatus.UNAUTHORIZED, login_page("Invalid credentials.", "login"))
            return
        token, name, role = result
        log(f"result: LOGIN BYPASSED -> signed in as {name!r} role={role!r}")
        cookie = f"{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax"
        self._redirect("/admin", cookie=cookie)


def loopback_address(host: str) -> bool:
    """True only for a loopback bind address (the app refuses to listen anywhere else)."""
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Deliberately vulnerable lab login app (HDD HK1 rehearsal only)."
    )
    parser.add_argument(
        "--host",
        default=os.environ.get("HDD_VULN_HOST", HOST_DEFAULT),
        help="bind address; must be loopback (default 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("HDD_VULN_PORT", str(PORT_DEFAULT))),
        help="listen port (default 8081)",
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    sys.stdout.reconfigure(line_buffering=True)
    print(BANNER, flush=True)
    if not loopback_address(args.host):
        log(
            f"refusing to bind non-loopback address {args.host!r}: this app must "
            "never be exposed beyond the machine (lab rule)."
        )
        return 2
    try:
        server = ThreadingHTTPServer((args.host, args.port), Handler)
    except OSError as exc:
        log(
            f"cannot listen on {args.host}:{args.port}: {exc}. "
            "Is another process using that port? Set HDD_VULN_PORT to change it."
        )
        return 1
    server.daemon_threads = True
    log("seeded fake users with random passwords (printed once per run):")
    for username, password, role in STATE.credentials:
        log(f"  username={username} password={password} role={role}")
    log(f"listening on http://{args.host}:{args.port}/login (loopback only)")
    log("this app is the deliberately vulnerable 'without HDD' target; never expose it.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        log("stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

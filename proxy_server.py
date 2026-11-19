#!/usr/bin/env python3
import base64
import binascii
from collections import deque
import hmac
import html
from html.parser import HTMLParser
import ipaddress
import math
import os
import re
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, quote, urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler as NoProxyHandler, Request, build_opener


ALLOWED_DOMAINS = {
    "google.com",
    "google.co.jp",
    "x.com",
    "spotify.com",
}
MAX_URL_LENGTH = 4096
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
FETCH_TIMEOUT_SECONDS = 15
AUTH_FAILURE_LIMIT = 5
AUTH_FAILURE_WINDOW_SECONDS = 300
_AUTH_FAILURES = {}
_AUTH_FAILURES_LOCK = threading.Lock()


def valid_target_url(url):
    if not isinstance(url, str) or len(url) > MAX_URL_LENGTH:
        return False
    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
        return (
            parsed.scheme == "https"
            and hostname is not None
            and any(
                hostname == domain or hostname.endswith(f".{domain}")
                for domain in ALLOWED_DOMAINS
            )
            and parsed.port in (None, 443)
            and parsed.username is None
            and parsed.password is None
        )
    except ValueError:
        return False


def validate_credentials(user, password):
    return bool(
        re.fullmatch(r"[A-Za-z0-9._-]{1,64}", user)
        and len(password) >= 32
        and password.isprintable()
    )


class SafeRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        if not valid_target_url(new_url):
            raise HTTPError(new_url, 403, "Redirect destination is not allowed", headers, response)
        return super().redirect_request(request, response, code, message, headers, new_url)


class LinkRewriter(HTMLParser):
    def __init__(self, base_url):
        super().__init__(convert_charrefs=False)
        self.base_url = base_url
        self.parts = []

    def _render_tag(self, tag, attrs, close):
        rendered_attrs = []
        for name, value in attrs:
            if value is not None and name in {"href", "src", "action"}:
                target = urljoin(self.base_url, value)
                if valid_target_url(target):
                    value = "/fetch?url=" + quote(target, safe="")
            rendered_attrs.append(
                f" {name}" if value is None else f' {name}="{html.escape(value, quote=True)}"'
            )
        self.parts.append(f"<{tag}{''.join(rendered_attrs)}{close}")

    def handle_starttag(self, tag, attrs):
        self._render_tag(tag, attrs, ">")

    def handle_startendtag(self, tag, attrs):
        self._render_tag(tag, attrs, "/>")

    def handle_endtag(self, tag):
        self.parts.append(f"</{tag}>")

    def handle_data(self, data):
        self.parts.append(data)

    def handle_entityref(self, name):
        self.parts.append(f"&{name};")

    def handle_charref(self, name):
        self.parts.append(f"&#{name};")

    def handle_comment(self, data):
        self.parts.append(f"<!--{data}-->")

    def handle_decl(self, decl):
        self.parts.append(f"<!{decl}>")

    def handle_pi(self, data):
        self.parts.append(f"<?{data}>")

    def get_html(self):
        return "".join(self.parts)


class ProxyHandler(BaseHTTPRequestHandler):
    server_version = "ActionsWebProxy"

    def log_message(self, _format, *_args):
        return

    def _send(self, status, body=b"", content_type="text/plain; charset=utf-8", headers=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _client_ip(self):
        forwarded_ip = self.headers.get("CF-Connecting-IP", "").strip()
        try:
            return str(ipaddress.ip_address(forwarded_ip))
        except ValueError:
            return self.client_address[0]

    def _authenticate(self):
        user = os.environ.get("PROXY_USER", "")
        password = os.environ.get("PROX_PASS", "")
        valid_credentials = validate_credentials(user, password)
        header = self.headers.get("Authorization", "")
        scheme, _, encoded = header.partition(" ")
        provided = ""
        if scheme.lower() == "basic":
            try:
                provided = base64.b64decode(encoded, validate=True).decode("utf-8")
            except (binascii.Error, UnicodeDecodeError):
                pass
        expected = f"{user}:{password}"
        is_valid = valid_credentials and hmac.compare_digest(provided, expected)
        client_ip = self._client_ip()
        now = time.monotonic()

        with _AUTH_FAILURES_LOCK:
            failures = _AUTH_FAILURES.get(client_ip, deque())
            while failures and now - failures[0] >= AUTH_FAILURE_WINDOW_SECONDS:
                failures.popleft()
            if len(failures) >= AUTH_FAILURE_LIMIT:
                retry_after = math.ceil(
                    AUTH_FAILURE_WINDOW_SECONDS - (now - failures[0])
                )
                _AUTH_FAILURES[client_ip] = failures
                return False, retry_after
            if is_valid:
                _AUTH_FAILURES.pop(client_ip, None)
                return True, 0
            failures.append(now)
            _AUTH_FAILURES[client_ip] = failures
            return False, 0

    def _require_auth(self):
        authorized, retry_after = self._authenticate()
        if authorized:
            return True
        if retry_after:
            self._send(
                429,
                b"Too many failed authentication attempts",
                headers={"Retry-After": str(retry_after)},
            )
            return False
        self._send(
            401,
            b"Authentication required",
            headers={"WWW-Authenticate": 'Basic realm="Actions web proxy"'},
        )
        return False

    def do_GET(self):
        if self.path == "/healthz":
            self._send(200, b"ok")
            return
        if not self._require_auth():
            return
        if self.path == "/" or self.path.startswith("/?"):
            self._send(200, self._home_page(), "text/html; charset=utf-8")
            return
        if self.path.startswith("/fetch?"):
            self._fetch_target()
            return
        self._send(404, b"Not found")

    def _home_page(self):
        return b"""<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Temporary web proxy</title>
<body>
<h1>Temporary web proxy</h1>
<p>Only HTTPS pages on Google, X, and Spotify domains are fetched through this server.
Other destinations, POST requests, and sign-in flows are not supported.</p>
<form action="/fetch" method="get">
  <label for="url">URL</label>
  <input id="url" name="url" type="url" value="https://www.google.com/" required>
  <button type="submit">Open through proxy</button>
</form>
</body>
</html>"""

    def _fetch_target(self):
        query = parse_qs(urlsplit(self.path).query, keep_blank_values=True)
        targets = query.get("url", [])
        if len(targets) != 1 or not valid_target_url(targets[0]):
            self._send(400, b"URL must be HTTPS on google.com, google.co.jp, x.com, or spotify.com")
            return

        request = Request(
            targets[0],
            headers={
                "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
                "Accept-Encoding": "identity",
                "User-Agent": "Mozilla/5.0 (compatible; ActionsWebProxy/1.0)",
            },
        )
        opener = build_opener(NoProxyHandler({}), SafeRedirectHandler())
        try:
            with opener.open(request, timeout=FETCH_TIMEOUT_SECONDS) as response:
                body = response.read(MAX_RESPONSE_BYTES + 1)
                content_type = response.headers.get("Content-Type", "application/octet-stream")
                status = response.status
        except HTTPError as error:
            self._send(error.code, b"Google returned an HTTP error")
            return
        except (URLError, TimeoutError, OSError) as error:
            print(f"Upstream request failed: {type(error).__name__}", file=sys.stderr)
            self._send(502, b"Could not fetch the requested Google page")
            return

        if len(body) > MAX_RESPONSE_BYTES:
            self._send(502, b"Upstream response exceeded the size limit")
            return

        if content_type.lower().startswith("text/html"):
            charset = "utf-8"
            match = re.search(r"charset=([A-Za-z0-9._-]+)", content_type, re.IGNORECASE)
            if match:
                charset = match.group(1)
            try:
                document = body.decode(charset)
                rewriter = LinkRewriter(targets[0])
                rewriter.feed(document)
                body = rewriter.get_html().encode("utf-8")
                content_type = "text/html; charset=utf-8"
            except (LookupError, UnicodeDecodeError):
                self._send(502, b"Could not decode the upstream HTML page")
                return

        self._send(status, body, content_type)


def main():
    user = os.environ.get("PROXY_USER", "")
    password = os.environ.get("PROX_PASS", "")
    if not validate_credentials(user, password):
        raise SystemExit(
            "Set PROXY_USER (1-64 allowed characters) and "
            "PROX_PASS (at least 32 printable characters)."
        )
    server = ThreadingHTTPServer(("127.0.0.1", 8080), ProxyHandler)
    print("Web proxy listening on 127.0.0.1:8080")
    server.serve_forever()


if __name__ == "__main__":
    main()

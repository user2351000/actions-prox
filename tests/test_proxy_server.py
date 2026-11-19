import base64
import os
import threading
import unittest
from http.server import ThreadingHTTPServer
from unittest.mock import MagicMock, patch
from urllib.request import Request, urlopen
from urllib.error import HTTPError

from proxy_server import (
    _AUTH_FAILURES,
    _AUTH_FAILURES_LOCK,
    LinkRewriter,
    ProxyHandler,
    valid_target_url,
    validate_credentials,
)


class TargetValidationTests(unittest.TestCase):
    def test_allows_only_https_urls_on_permitted_domains(self):
        self.assertTrue(valid_target_url("https://www.google.com/search?q=test"))
        self.assertTrue(valid_target_url("https://google.co.jp/"))
        self.assertTrue(valid_target_url("https://x.com/"))
        self.assertTrue(valid_target_url("https://www.x.com/"))
        self.assertTrue(valid_target_url("https://open.spotify.com/"))
        self.assertTrue(valid_target_url("https://accounts.spotify.com/"))
        self.assertFalse(valid_target_url("http://www.google.com/"))
        self.assertFalse(valid_target_url("https://example.com/"))
        self.assertFalse(valid_target_url("https://www.google.com.evil.example/"))
        self.assertFalse(valid_target_url("https://x.com.evil.example/"))
        self.assertFalse(valid_target_url("https://spotify.com.evil.example/"))
        self.assertFalse(valid_target_url("https://user:pass@www.google.com/"))
        self.assertFalse(valid_target_url("https://www.google.com:444/"))

    def test_rewrites_only_allowlisted_links(self):
        parser = LinkRewriter("https://www.google.com/search?q=test")
        parser.feed(
            '<a href="/search?q=next">Next</a>'
            '<a href="https://example.com/">External</a>'
        )
        output = parser.get_html()
        self.assertIn('/fetch?url=https%3A%2F%2Fwww.google.com%2Fsearch%3Fq%3Dnext', output)
        self.assertIn('href="https://example.com/"', output)


class CredentialValidationTests(unittest.TestCase):
    def test_accepts_long_passwords_with_symbols_and_spaces(self):
        self.assertTrue(validate_credentials("testuser", "aB3!@#$%^&*()_+-=[]{} " * 2))

    def test_rejects_short_or_non_printable_passwords(self):
        self.assertFalse(validate_credentials("testuser", "short"))
        self.assertFalse(validate_credentials("testuser", "a" * 31 + "\n"))


class AuthenticationTests(unittest.TestCase):
    def setUp(self):
        self.password = "aB3!@#$%^&*()_+-=[]{} " * 2
        with _AUTH_FAILURES_LOCK:
            _AUTH_FAILURES.clear()
        self.env = patch.dict(
            os.environ,
            {
                "PROXY_USER": "testuser",
                "PROX_PASS": self.password,
            },
        )
        self.env.start()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), ProxyHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.env.stop()

    def test_home_page_requires_basic_auth(self):
        with self.assertRaises(HTTPError) as error:
            urlopen(f"{self.base_url}/")
        self.assertEqual(error.exception.code, 401)
        error.exception.close()

        credentials = base64.b64encode(f"testuser:{self.password}".encode()).decode()
        request = Request(
            f"{self.base_url}/",
            headers={"Authorization": f"Basic {credentials}"},
        )
        with urlopen(request) as response:
            self.assertEqual(response.status, 200)
            self.assertIn(b"Temporary web proxy", response.read())

    def test_fetch_rejects_destinations_outside_allowlist(self):
        credentials = base64.b64encode(f"testuser:{self.password}".encode()).decode()
        request = Request(
            f"{self.base_url}/fetch?url=https%3A%2F%2Fexample.com%2F",
            headers={"Authorization": f"Basic {credentials}"},
        )
        with self.assertRaises(HTTPError) as error:
            urlopen(request)
        self.assertEqual(error.exception.code, 400)
        error.exception.close()

    def test_fetch_returns_permitted_html_with_internal_links_rewritten(self):
        credentials = base64.b64encode(f"testuser:{self.password}".encode()).decode()
        request = Request(
            f"{self.base_url}/fetch?url=https%3A%2F%2Fwww.google.com%2Fsearch%3Fq%3Dtest",
            headers={"Authorization": f"Basic {credentials}"},
        )
        upstream = MagicMock()
        upstream.__enter__.return_value = upstream
        upstream.__exit__.return_value = False
        upstream.read.return_value = b'<a href="/search?q=next">Next</a>'
        upstream.headers.get.return_value = "text/html; charset=utf-8"
        upstream.status = 200
        opener = MagicMock()
        opener.open.return_value = upstream

        with patch("proxy_server.build_opener", return_value=opener):
            with urlopen(request) as response:
                body = response.read()

        self.assertIn(
            b'/fetch?url=https%3A%2F%2Fwww.google.com%2Fsearch%3Fq%3Dnext',
            body,
        )

    def test_repeated_bad_passwords_are_rate_limited_by_client_ip(self):
        for _ in range(5):
            with self.assertRaises(HTTPError) as error:
                urlopen(f"{self.base_url}/")
            self.assertEqual(error.exception.code, 401)
            error.exception.close()

        with self.assertRaises(HTTPError) as error:
            urlopen(f"{self.base_url}/")
        self.assertEqual(error.exception.code, 429)
        self.assertGreater(int(error.exception.headers["Retry-After"]), 0)
        error.exception.close()

    def test_successful_authentication_clears_failed_attempts(self):
        for _ in range(4):
            with self.assertRaises(HTTPError) as error:
                urlopen(f"{self.base_url}/")
            self.assertEqual(error.exception.code, 401)
            error.exception.close()

        credentials = base64.b64encode(f"testuser:{self.password}".encode()).decode()
        request = Request(
            f"{self.base_url}/",
            headers={"Authorization": f"Basic {credentials}"},
        )
        with urlopen(request) as response:
            self.assertEqual(response.status, 200)

        with self.assertRaises(HTTPError) as error:
            urlopen(f"{self.base_url}/")
        self.assertEqual(error.exception.code, 401)
        error.exception.close()


if __name__ == "__main__":
    unittest.main()

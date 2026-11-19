# actions-prox

A temporary, browser-based web proxy for Google, X, and Spotify running on GitHub Actions. It uses a Cloudflare Quick Tunnel; the client needs only a browser, not Tailscale or a browser extension.

## Setup

1. In **Settings → Secrets and variables → Actions**, add:
   - `PROXY_USER`: 1-64 letters, digits, dots, underscores, or hyphens.
   - `PROX_PASS`: at least 32 printable characters. Symbols and spaces are allowed; control characters are not.
2. Open **Actions → Start browser web proxy → Run workflow**.
3. Open the `trycloudflare.com` URL printed in the workflow log and enter the secret credentials when prompted.
4. Enter a URL on Google, X, or Spotify. The proxy fetches the page server-side and returns it to the browser.

## Limitations and security

- Only HTTPS URLs on `google.com`, `google.co.jp`, `x.com`, and `spotify.com` and their subdomains are allowed. This is deliberately not an open proxy.
- The proxy supports GET requests only. Sign-in, POST forms, and assets hosted outside the allowed domains may not work.
- The Quick Tunnel URL is public and changes on each run. Basic authentication is required; keep the credentials private.
- The workflow runs only while the Actions job is active and is configured to stop after six hours. Quick Tunnels are for testing and development, have no uptime guarantee, and the URL becomes inactive when the job ends.
- This is a temporary experiment, not a persistent or production web proxy. Do not enter sensitive information.

Cloudflare Quick Tunnel does not require an account or domain. See the [Quick Tunnel documentation](https://developers.cloudflare.com/tunnel/get-started/quick-tunnels/).

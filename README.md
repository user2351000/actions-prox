# actions-prox

A temporary, browser-based Google web proxy running on GitHub Actions. It uses a Cloudflare Quick Tunnel; the client needs only a browser, not Tailscale or a browser extension.

## Setup

1. In **Settings → Secrets and variables → Actions**, add:
   - `PROXY_USER`: 1-64 letters, digits, dots, underscores, or hyphens.
   - `PROXY_PASSWORD`: at least 32 letters, digits, underscores, or hyphens.
2. Open **Actions → Start browser web proxy → Run workflow**.
3. Open the `trycloudflare.com` URL printed in the workflow log and enter the secret credentials when prompted.
4. Enter a Google URL. The proxy fetches the page server-side and returns it to the browser.

## Limitations and security

- Only HTTPS URLs on `google.com`, `www.google.com`, `google.co.jp`, and `www.google.co.jp` are allowed. This is deliberately not an open proxy.
- The proxy supports GET requests only. Google sign-in, POST forms, and some assets or links may not work.
- The Quick Tunnel URL is public and changes on each run. Basic authentication is required; keep the credentials private.
- The workflow runs only while the Actions job is active and is configured to stop after six hours. Quick Tunnels are for testing and development, have no uptime guarantee, and the URL becomes inactive when the job ends.
- This is a temporary experiment, not a persistent or production web proxy. Do not enter sensitive information.

Cloudflare Quick Tunnel does not require an account or domain. See the [Quick Tunnel documentation](https://developers.cloudflare.com/tunnel/get-started/quick-tunnels/).

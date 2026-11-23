# Frontend gateway readiness

The Node frontend serves the checked-out app and forwards the two existing
backend routes. It has no npm runtime dependencies and does not need a build
step. The repository directory is resolved from the server module, so startup
works from the checkout or a different working directory; `/app` is not required.

```sh
HOST=127.0.0.1 PORT=3000 REACT_APP_BACKEND_URL=http://127.0.0.1:8001 \
  node frontend/server.mjs
```

The backend URL must be a complete HTTP(S) origin without user information,
query parameters, fragments, or a path. HTTPS uses Node's certificate and
hostname verification. An approved private CA can be supplied using Node's
`NODE_EXTRA_CA_CERTS` at process startup. Never disable TLS verification.
Local `.env` loading is relative to `frontend/server.mjs`; explicit environment
variables take precedence.

## Request behavior

- Known HTML, JavaScript, CSS and brand-image paths support GET and HEAD with
  their correct content types. Unknown paths return 404 with a no-index header.
  Repository source, configuration and private data are not served.
- Malformed percent encoding, absolute request targets, authority paths and
  control characters return 400 without terminating the process.
- Only GET `/api/health` and POST `/api/ai/audit` are proxied. Unknown API routes,
  query strings and alternate API path encodings are rejected. Unsupported
  methods return 405 with Allow.
- The upstream host is fixed by server configuration. Only Authorization,
  Content-Type, Accept and Origin are forwarded from callers. Cookies and
  caller-supplied Host, forwarding headers, roles and scope headers are omitted.
- Backend authentication errors and Retry-After are preserved. With owner mode
  disabled, caller Authorization is forwarded as before. The optional owner
  adapter uses only its configured server-held scoped credential after owner
  session/CSRF checks; a caller Authorization header is rejected in that mode.
  Upstream cookies and arbitrary upstream headers are not exposed to browsers.
- Request bodies are bounded to 256 KiB and ten seconds. Upstream responses
  have a 95-second total deadline, a 65-second idle deadline and a 2 MiB bound.
  SSE bytes remain streaming. A failure after response headers closes the
  incomplete stream; it cannot be reported as a completed AI analysis.
- Disconnected clients release the upstream request. Connection failures return
  502 and pre-header response timeouts return 504 with sanitized details.

## Deployment boundary

The optional single-owner adapter is described in
[OWNER-SESSION-GATEWAY.md](OWNER-SESSION-GATEWAY.md). It is disabled unless an
owner-only configuration file is supplied. Its login UI honestly reports that
configuration state. The hardened backend still requires registered bearer
tokens, scopes, approved transport, network/origin policies, MongoDB and private
audit storage. The public deterministic demo remains usable without an AI
provider. Do not put a service token in HTML, JavaScript or browser storage.

This frontend intentionally strips X-Forwarded-Proto. It must not be registered
as a TLS-attesting proxy for the backend. Use direct verified HTTPS, or a reviewed
TLS gateway that overwrites its own forwarding headers. Loopback HTTP is for
local private use. The source change does not deploy or restart a live service.

## Fresh validation on November 23, 2026

`node --test frontend/tests/gateway.test.mjs` passes all ten black-box tests,
including real local HTTPS with a temporary trusted certificate, rejection of
an untrusted certificate, malformed-path recovery, exact asset serving,
authentication/header isolation, SSE streaming, oversized/slow requests,
upstream failure/deadline handling, and interrupted/oversized responses.

These tests run as part of `npm test` and therefore run in the existing Node
CI and public-build gate. Their TLS fixture needs the OpenSSL command available
on the test host. They contact only disposable loopback servers, use synthetic
data, and make no paid provider calls.

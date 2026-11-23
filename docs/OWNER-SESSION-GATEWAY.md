# Optional owner login for browser AI

The Node frontend can now authenticate one explicitly configured owner and
submit the two existing backend routes using a credential held only by the
server. The default remains disabled: no account, password, session or backend
credential is invented. The local deterministic audit works in either mode.
The public GitHub Pages artifact still uses `public-demo.html`; the owner UI is
the separately hosted Node frontend's `index.html`.

## Boundaries

- The owner ID and scrypt password hash are configured in a private file.
  The backend bearer token lives in a separate private file. Both must be
  absolute paths to regular files owned by the process user, mode 0600, with
  one link; symlinks, hardlinks, oversized files and shared-readable files are
  rejected. Configuration and token contents are never served as static files.
- Password derivation uses asynchronous scrypt, N=131072, r=8, p=1, a random
  16-byte salt and a 32-byte hash. The KDF memory bound is 160 MiB and only one
  derivation runs at a time. Setup accepts 12–1024 UTF-8 bytes; passwords never
  enter argv or an environment variable in the documented setup.
- Login is limited to five attempts per socket peer and twenty total attempts
  per fifteen minutes. Forwarded IP headers cannot reset the limit. Peer state
  is bounded to 128 entries. A loopback TLS proxy deliberately shares one peer
  limit for this single-owner service.
- Sessions use random 256-bit IDs; the server stores their SHA-256 digests.
  Cookies use `__Host-`, Secure, HttpOnly, SameSite=Strict and Path=/, with no
  Domain attribute. A session expires after thirty idle minutes or eight hours
  total. Login rotates the prior cookie's session; logout invalidates it.
- At most sixteen sessions are retained in memory. Restart invalidates all
  sessions and resets the local login counters. This is a single-process owner
  adapter, not a distributed identity service. Do not run independent workers
  behind a load balancer and assume shared sessions or attempt limits.
- Login requires exact configured HTTPS Host/Origin and JSON. Audit/logout
  additionally require the current session's CSRF nonce. Cross-site fetches,
  alternate path encodings and query parameters are rejected. CSRF lives only
  in the page's memory; the browser never receives the backend bearer token.
- Owner mode accepts only verified HTTPS or numeric private loopback HTTP for
  the backend hop. Existing backend principal scopes (`health:read`,
  `audit:run`), token expiry, transport, host/network/origin policy, shared
  budgets and durable audit enforcement remain authoritative. The configured
  backend principal should identify this owner adapter and have only the scopes
  needed by its routes. No browser field or role header changes those scopes.

## Configure on the intended host

Do not run this setup as part of the public static build. Keep the private
directory outside the document root and repository. The following paths are
examples to adapt to the process owner's deployment; no real credential was
created by this change.

1. Register a dedicated expiring backend principal using the existing
   [backend security procedure](BACKEND-SECURITY.md). Save its bearer token in
   `/srv/watchdawg-private/owner-backend-token`, owned by the frontend user,
   mode 0600. The backend policy must approve the actual upstream transport,
   frontend origin and network peer.
2. Hash a password locally from a hidden Bash prompt. The hash output is also
   private. `set -C` below refuses to overwrite an existing file.

   ```sh
   umask 077
   set -C
   read -r -s -p 'Owner password: ' watchdawg_owner_password
   printf '\n'
   printf '%s' "$watchdawg_owner_password" | node frontend/hash-owner-password.mjs > /srv/watchdawg-private/owner-password.hash
   unset watchdawg_owner_password
   ```

3. Create `/srv/watchdawg-private/owner-session.json` with mode 0600, replacing
   the owner ID, public origin and hash placeholder deliberately:

   ```json
   {
     "owner_id": "chosen-owner-id",
     "password_hash": "COPY_THE_LOCALLY_CREATED_SCRYPT_HASH",
     "backend_token_file": "/srv/watchdawg-private/owner-backend-token",
     "public_origin": "https://watchdawg.example.invalid",
     "trusted_proxy_addresses": []
   }
   ```

4. Prefer direct frontend TLS with certificate/key files owned by its process
   user (mode 0600). The certificate must be valid for the configured origin.

   ```sh
   HOST=127.0.0.1 PORT=3000 \
   REACT_APP_BACKEND_URL=https://backend.example.invalid \
   WATCHDAWG_OWNER_CONFIG_FILE=/srv/watchdawg-private/owner-session.json \
   FRONTEND_TLS_CERT_FILE=/srv/watchdawg-private/frontend-cert.pem \
   FRONTEND_TLS_KEY_FILE=/srv/watchdawg-private/frontend-key.pem \
   node frontend/server.mjs
   ```

   When a cPanel/other TLS ingress terminates HTTPS, instead bind the frontend
   HTTP listener to loopback and explicitly configure only the loopback address
   used by that proxy (`127.0.0.1` and/or `::1`). The ingress must overwrite Host
   with the configured public host and replace X-Forwarded-Proto with exactly
   `https`; it must never append or pass through a caller's value. This trust
   option assumes other processes on that host cannot impersonate the proxy.
   No remote proxy address or automatic forwarded-header trust is accepted.
   The frontend still strips all forwarded headers on its backend hop.

The example domain names are placeholders. Configure actual TLS, origin,
backend principal and a valid owner password on the intended host before
claiming browser AI is deployed. The backend may still deny access or be
unavailable; signing into the frontend does not bypass those decisions.

## Browser behavior and cancellation

The owner form is shown only when configured. The password field is cleared
on submission. Login/logout mutations are serialized so a delayed login cookie
is revoked before a requested logout completes. Session changes/deadlines
abort older audits, clear their output and ignore stale session/error responses.
Each authentication fetch and its JSON body share a ten-second client deadline;
a broken connection cannot hold a pending login/mutation forever. That deadline
does not shorten the separately bounded streaming AI request.
An unconfirmed logout remains visibly unconfirmed and locally blocks new AI
requests until retried; it does not claim server-side revocation succeeded.

Audit requests retain the input snapshot used for their deterministic result.
The Run button explicitly invokes the audit options instead of accidentally
passing a MouseEvent as those options. Invalid JSON never requests AI.

Streaming output is complete only after a valid SSE `done: true` frame and a
clean end of stream. EOF without that frame, truncated frames, provider error
frames, oversized streams and stale requests never display successful analysis.
An upstream Bearer challenge identifies a backend authorization problem, which
does not discard a valid owner login and cause a misleading sign-in loop.

## Validation

`npm test` includes actual loopback HTTP/TLS security tests and client race/SSE
tests. All use synthetic credentials and provider responses. They exercise
configuration permissions/links, origin and CSRF rejection, secret isolation,
backend header/scoping boundaries, cookie rotation, idle/absolute expiry,
attempt limits, logout/login/late-response races and explicit stream completion.

```sh
npm ci --ignore-scripts
npm test
npx playwright install --with-deps chromium
npm run test:owner-browser
```

The dedicated CI workflow runs a real Chromium browser against a temporary
HTTPS server and synthetic SSE backend. It exercises disabled mode, owner
login and cookie flags, credential non-disclosure, delayed input snapshots,
incomplete streams, logout during streaming, expiry during an outstanding
request, and mobile layout. Its temporary self-signed certificate is accepted
only by that test browser context; the HTTP/TLS tests separately verify that
untrusted certificates are rejected. Results/screenshots are retained as CI
artifacts. A locally installed browser can be selected explicitly with
`WATCHDAWG_TEST_CHROMIUM_PATH`; this selects a browser executable without
changing product authentication.

No real provider, customer data or paid call is used in acceptance. Runtime
owner/TLS/backend configuration and real-owner acceptance remain deployment
steps. The existing backend `production_approved=false` gate is unchanged.

The native Android 0.3.1 APK remains tied to source
`63027534a2f8cc953f9eed7e707cf0fed0b30dce`, merged as
`069cb43f58bd0d4a39585d22db41eed3416195f8`. That APK has no HTML/JavaScript or
WebView bundle; this later Node/browser feature does not change its native
source or establish Play/physical-device readiness.

Design references:

- [Node crypto scrypt and timing-safe comparison](https://nodejs.org/api/crypto.html)
- [OWASP password storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [OWASP session management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [OWASP CSRF prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)

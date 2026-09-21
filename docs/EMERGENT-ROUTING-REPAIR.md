# Emergent fail-closed routing repair

## Status

The live deployment is still blocked from release acceptance.

Last verified: `2026-09-21T12:26:35Z`

Live origin: `https://watch-dawg.emergent.host`

Emergent job ID: `7d93f5cb-d7fd-45ce-8b2a-f7f68bf1382e`

## Verified mismatch

The live frontend is not the frontend artifact represented by the current repository server contract.

| Surface | Observed artifact |
| --- | --- |
| Live `/` | 451-byte HTML shell, SHA-256 prefix `36fde07f1099b1b5`, ETag `"6a90142b-1c3"`, last modified August 27, 2026 |
| Live assets | `/app.js` (`e4babec2f3d9f414`), `/styles.css` (`9862d90d5bc4d33c`), `/favicon.svg` (`2ceee489a1a90e33`) |
| Repository `main` at inspection | commit `d2997c40249bc07444c369f50e2f9c1d59b71e19` |
| Repository root artifact | `index.html` is 27,133 bytes, SHA-256 `acdb7431b43b2081`; its JavaScript asset is `/watchdawg.js` |
| Repository server | `frontend/server.mjs` allowlists only `/`, `/index.html`, and `/watchdawg.js`, then returns 404 for every other static path |

No reachable repository branch contains the live title `Watch-Dawg AI | Contractor Audit Demo` or its `app.js/styles.css/favicon.svg` bundle. The repository contains only the Emergent job ID; it does not contain a production deployment revision, a production build manifest, or the command that created the live image.

The live app bundle uses in-page view state and does not use the History API, `location.pathname`, or a `popstate` handler. There is therefore no documented client route that needs a blanket SPA fallback.

## Root cause

Two independent mismatches are present:

1. **Artifact drift:** the live static bundle came from an older or uncommitted Emergent workspace snapshot, not the current GitHub artifact.
2. **Routing-layer drift:** the production static frontend layer is applying a catch-all equivalent to `try_files $uri /index.html`, so requests never reach the repository's fail-closed Node static handler.

The healthy live `/api/health` response shows that the API route is still reaching the backend. This is a frontend static-routing defect, not evidence of a backend compromise.

## Smallest safe live repair

Preserve the current contractor demo bundle and change only the active production frontend routing rule. Do **not** redeploy GitHub `main` merely to close this issue: that would replace the visible frontend and is a broader release decision.

Before editing, inspect the actual Emergent job workspace and deployment pane:

```bash
git status --short --branch
git rev-parse HEAD
find /app/frontend -maxdepth 3 -type f -print | sort
cat /app/frontend/package.json
sudo supervisorctl status
sudo nginx -T
```

Match the deployed files to the live fingerprints before treating that workspace as the source artifact. Record the current production deployment/revision as the rollback target. If the deployment pane cannot restore the current revision, stop and have Emergent support confirm a rollback path before redeploying.

For an Nginx-served copy of the current live artifact, keep the existing `/api/` proxy unchanged and replace only the frontend SPA fallback with the following behavior:

```nginx
location = / {
    try_files /index.html =404;
}

location = /index.html {
    try_files $uri =404;
}

location = /app.js {
    try_files $uri =404;
}

location = /styles.css {
    try_files $uri =404;
}

location = /favicon.svg {
    try_files $uri =404;
}

location / {
    add_header X-Robots-Tag "noindex, nofollow" always;
    default_type text/plain;
    return 404 "Not found\n";
}
```

The existing API location must remain ahead of that catch-all. Do not introduce a replacement fallback, wildcard asset rewrite, redirect to `/`, or application-level 200 error page.

If the effective production Nginx/ingress configuration is platform-controlled, the corresponding Emergent support request is:

> For job `7d93f5cb-d7fd-45ce-8b2a-f7f68bf1382e` and deployment `watch-dawg.emergent.host`, disable the frontend SPA catch-all. Preserve `/` plus the existing `index.html`, `app.js`, `styles.css`, and `favicon.svg` files, preserve the existing `/api/` proxy, and return a genuine HTTP 404 with `X-Robots-Tag: noindex, nofollow` for every other frontend path. No client-side routes require fallback. Please identify the production source revision and the rollback revision before applying the change.

## Verification gate

Run the repository gate before redeployment:

```bash
npm test
node --check frontend/server.mjs
python -m compileall -q backend
python -m flake8 backend/server.py backend/tests/test_ai_audit_api.py
```

Run the live matrix immediately after deployment:

```bash
npm run verify:emergent-routing -- https://watch-dawg.emergent.host
```

The verifier discovers same-origin assets from the root HTML, checks their MIME types, checks `/api/health`, creates a unique missing route, and checks nested missing asset paths. It fails unless all missing responses are genuine 404s with `X-Robots-Tag: noindex`.

Acceptance requires:

- `/` remains `200 text/html`.
- Every asset referenced by `/` remains `200` with its correct non-HTML MIME type.
- `/api/health` remains `200 application/json`.
- The unique missing route returns 404 with `X-Robots-Tag: noindex`.
- Nested missing `app.js`, `styles.css`, `favicon.svg`, and discovered asset names return 404, never the root HTML with status 200.

Roll back immediately if the root, any known asset, or `/api/health` fails. Do not close Issue #8 from a preview-only pass; attach the passing production matrix and the deployed revision to the issue.

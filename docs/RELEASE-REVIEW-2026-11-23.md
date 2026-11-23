# Release integration review — November 23, 2026

## Frontend and fresh security findings

The gateway repair and its ten black-box tests are documented in
[FRONTEND-GATEWAY.md](FRONTEND-GATEWAY.md). The first hosted run on `3c8c75c`
passed Node, Python, backend integration, and government-evidence checks. Its
operations job correctly refused the TLS proxy image: the pinned Nginx 1.30.6
runtime now has six critical/high findings with a fixed stable version 1.30.7.
The vulnerability policy has not been weakened or bypassed.

The proxy base is updated to the official `nginx:stable-alpine` multi-platform
index `sha256:caf4e1e032a20f9c3c5e28fc7f25ffd768ad8677b4975c54193075997b3a97e3`.
The Docker Hub registry configuration for its Linux/amd64 member reports
`NGINX_VERSION=1.30.7`, `PKG_RELEASE=1`. The corresponding member digest is
`sha256:4d1d4ce08432dc7dfe4af762cb224ce6b5273ae878f41e020ea2425d02ea91a4`.

Primary evidence:

- [Nginx security advisories](https://nginx.org/en/security_advisories.html)
  identify 1.30.7 as fixed for CVE-2026-113425, CVE-2026-118899,
  CVE-2026-121810, CVE-2026-123007, CVE-2026-123633 and CVE-2026-123634.
- [First hosted integration run](https://github.com/bobhay75/Watch-Dawg-AI/actions/runs/45141164829)
  records the actual image-bound scanner failure and successful backend checks.
- Official registry: `registry-1.docker.io/v2/library/nginx/manifests/stable-alpine`,
  fetched with normal verified TLS on November 23, 2026. No image was published.

## Integration boundary

The intended integration order is PR #33 into secure operations, PR #32 into
the intelligence branch, then PR #27 into main. The intelligence branch already
contains the earlier PR #31 merge; use ordinary conflict-checked merges and
wait for the relevant final-head checks. Do not force-push or skip the scanner.

The main public Pages artifact, its source allowlist and field-desk data model
are unchanged by this release work. Backend changes introduce required
authentication, private audit storage and approved transports. Merging source
does not provision these settings or authorize reusing an unauthenticated
legacy backend configuration. The public static desk can release independently;
the private service still needs actual host configuration and recovery checks.

This record is a development integration review. A green image gate means the
configured blocking policy passed; it does not imply zero vulnerabilities,
external certification, validated production capacity, or completed operator
identity integration.

## Disposable database build deadline

The main-branch validation run
[45144984111](https://github.com/bobhay75/Watch-Dawg-AI/actions/runs/45144984111)
stopped while building the disposable MongoDB image: the cold image pull and
signed distribution updates exceeded the generic 120-second command limit.
This happened before the TLS/failover/restore assertions ran.

Both disposable runners now use a shared image-build helper with a bounded
600-second setup deadline and streamed Docker build output. Ordinary Docker
commands retain their 120-second limits, readiness polling keeps its existing
deadlines, and the operations workflow retains its 20-minute overall limit.
The pinned base image, package-signature checks, minimum patched versions, image
scans, private transport checks and recovery assertions remain enforced. Setup
timeouts and nonzero build exits still stop validation; the whole build is not
retried and there is no fallback image.

The first hosted run with streamed setup logs completed the recovery suite, but
the parallel backend job exposed another setup bottleneck: Ubuntu's HTTP
indexes, including unused universe and backports, took over six minutes to
download. The Dockerfile now requests only signed Ubuntu main, updates and
security indexes over HTTPS. Network requests have a 30-second timeout and at
most two transport retries within the unchanged 600-second overall build limit.
The MongoDB repository remains excluded and its server version stays pinned.

Offline regressions cover the original cold-build timing case, successful
execution of the pinned build command, termination of a stalled process, and
propagation of a nonzero build result. Hosted CI must also complete the full
real-database and recovery drills before this change is integrated.

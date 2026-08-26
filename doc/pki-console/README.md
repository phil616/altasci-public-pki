# PKI-Console

PKI-Console is an authenticated enterprise PKI control plane and React user
interface built directly on the CFSSL Go packages in this fork. It does not
execute CFSSL binaries and does not register the legacy unauthenticated
`/api/v1/cfssl/*` handlers.

For the complete Cloudflare Pages, external PostgreSQL, Cloudflare Tunnel and
systemd production procedure, see [production-deployment.md](production-deployment.md).
For tag-driven GitHub Releases and Wrangler deployment, see
[github-actions-release.md](github-actions-release.md).
For the current Cloudflare resources, completed Wrangler operations and
maintenance procedure, see
[cloudflare-wrangler-operations.md](cloudflare-wrangler-operations.md).
For daily checks, monitoring, backup/restore, rotation, rollback and incident
response, see [operations-runbook.md](operations-runbook.md). The resolved
2026-08-24 Access login incident is documented in
[incident-2026-08-24-access-login.md](incident-2026-08-24-access-login.md).
Reusable change, inspection, restore, rotation and incident forms are in
[operations-record-templates.md](operations-record-templates.md).
For the Web workflow that builds one root, two path-length-zero issuing CAs,
purpose-specific profiles and operator grants, see
[enterprise-pki-web-setup.md](enterprise-pki-web-setup.md).
For RFC 3161 time-stamping unit provisioning, client commands, clock health,
and failure behavior, see [tsa.md](tsa.md).
For native desktop integration through Cloudflare Managed OAuth, system-browser
Authorization Code + PKCE, local username/password login, session cookies, and
CSRF handling, see
[desktop-client-integration.md](desktop-client-integration.md).

## Native binary deployment

PKI-Console is distributed as a statically linked Go binary. It does not ship
or start an application container, database, or embedded persistence layer.
All persistent state is stored in the independently managed PostgreSQL instance
named by `DATABASE_URL`. The current production PostgreSQL happens to run in a
same-host 1Panel container; the PKI-Console application itself remains a native
systemd service.
Backups, replication, failover, connection routing, and storage encryption are
therefore owned by that database platform.

Build the current source tree with the Go toolchain declared in `go.mod`:

```sh
make pki-console
file bin/pki-console
```

`bin/pki-console` is built with `CGO_ENABLED=0`. Cross-compilation is supported,
for example `make pki-console TARGETOS=linux TARGETARCH=arm64`. Copy the binary
to the target host rather than installing or invoking a separate CFSSL binary:

```sh
install -o root -g root -m 0755 bin/pki-console /usr/local/bin/pki-console
```

Build the React 19 application with Node.js 20.19 or newer. `npm ci` uses the
committed lock file. Vite produces the static client bundle, while Wrangler
separately compiles the sibling `web/functions` proxy into the same Pages
deployment:

```sh
cd web
npm ci
npm run check
cd ..

# Or build the backend and frontend together.
make pki-console-system
```

Deploy `web/dist` and `web/functions` together from the `web` directory. Node.js
is not required on the Go production server:

```sh
cd web
npx --no-install wrangler pages deploy dist --project-name pki-web --branch main
```

Create the external PostgreSQL database and role using your database platform,
then copy `.env.example` to `/etc/pki-console/pki-console.env`, replace every
secret, and restrict the file to the service account. The sample zero keys are
format examples only and must never be used in any environment.

Run the idempotent migrations as an explicit deployment step, then start the
API:

```sh
set -a
. /etc/pki-console/pki-console.env
set +a

/usr/local/bin/pki-console migrate
/usr/local/bin/pki-console serve
```

The server includes an issuance worker. Additional, separately scalable worker
processes can run `/usr/local/bin/pki-console worker`; PostgreSQL `FOR UPDATE
SKIP LOCKED` prevents two workers from claiming the same request.

Production serves the same Pages build on `pki.altasci.com` and
`pki-console.altasci.com`. Pages Functions proxy only the REST, AIA, CRL, OCSP
and RFC 3161 TSA paths through `pki-origin.altasci.com` and Cloudflare Tunnel. The Go
process validates the shared origin secret and restores an allowlisted business
hostname, so no Nginx process is required. Protect only the Console hostname
with Cloudflare Access.

### Local web development

For a local PostgreSQL-backed service, use these development origins:

```sh
PKI_DEVELOPMENT_INSECURE='true'
PUBLIC_BASE_URL='http://pki.localhost:5173'
CONSOLE_BASE_URL='http://pki-console.localhost:5173'
```

Start the Go API on port 8080 and Vite on port 5173 in separate terminals:

```sh
./bin/pki-console serve

cd web
npm run dev
```

Open `http://pki-console.localhost:5173` for the authenticated Console and
`http://pki.localhost:5173` for the public PKI repository. Vite proxies only
the backend paths and preserves each hostname, so the same host-separation
checks apply during development. Real super-administrator login still requires
Cloudflare Access; development mode never bypasses Access JWT verification.

### systemd

A hardened unit is provided at `doc/pki-console/pki-console.service`. A typical
installation is:

```sh
useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin pki-console
install -d -o root -g pki-console -m 0750 /etc/pki-console
install -o root -g pki-console -m 0640 .env.example /etc/pki-console/pki-console.env
install -o root -g root -m 0644 doc/pki-console/pki-console.service /etc/systemd/system/pki-console.service

# Edit pki-console.env, provision the PostgreSQL TLS CA file, then migrate.
sudo -u pki-console env -i sh -c 'set -a; . /etc/pki-console/pki-console.env; exec /usr/local/bin/pki-console migrate'
systemctl daemon-reload
systemctl enable --now pki-console
```

Run migrations before every binary rollout. The service deliberately does not
apply versioned migrations during startup. The current audit writer can create
monthly partitions through `pki_create_audit_partition`, so the baseline
runtime role retains the schema privileges documented in the production guide.

## Required configuration

| Variable | Purpose |
| --- | --- |
| `DATABASE_URL` | Independently managed PostgreSQL URL; explicit same-host loopback may use `sslmode=disable`, remote production databases should use `verify-full` |
| `PUBLIC_BASE_URL` | Public AIA, CRL, OCSP and exact-lookup origin |
| `CONSOLE_BASE_URL` | Authenticated Console origin |
| `PKI_ORIGIN_SHARED_SECRET` | 64 hexadecimal characters shared only with the Pages Function; required in production |
| `ROOT_USER_EMAIL` | Unique super-administrator email |
| `ROOT_USER_PASSWORD` | Root password, at least 32 characters |
| `ROOT_USER_TOTP_SECRET` | Unpadded Base32 secret, at least 160 bits |
| `CF_ACCESS_TEAM_DOMAIN` | `https://<team>.cloudflareaccess.com` issuer |
| `CF_ACCESS_AUD` | Access application audience tag |
| `PKI_MASTER_KEY_ACTIVE_ID` | ID used for new AES-256-GCM envelopes |
| `PKI_MASTER_KEYS` | JSON map from key ID to Base64 32-byte KEK |
| `TRUSTED_PROXY_CIDRS` | Direct cloudflared peer networks; production normally trusts loopback only |
| `TSA_MAX_CLOCK_UNCERTAINTY` | Maximum Linux kernel NTP uncertainty accepted for RFC 3161 issuance; defaults to `5s` |

`PKI_DEVELOPMENT_INSECURE=true` allows HTTP base URLs only for local testing.
It does not disable Cloudflare JWT checks for the root account.

The program reads configuration directly from the process environment. It does
not parse `.env` files itself; a service manager or shell must load the file.
It does not create a local data directory or persist application PKI data
outside PostgreSQL; the operator-managed environment file is the only local
configuration shown here and must remain access-restricted.

## Security boundaries

- Root logins require password, RFC 6238 HMAC-SHA-256 TOTP, a valid Access JWT,
  and matching email in the JWT, Access email header, and root configuration.
- Every root API request revalidates the Access JWT. Root CA key export also
  requires a fresh password and a non-replayed TOTP step.
- Operator grants can target intermediate CAs only. A requester cannot approve
  their own request.
- CA keys use versioned AES-256-GCM envelopes in PostgreSQL. The KEK exists only
  in the process environment. OCSP uses a separate delegated responder
  certificate and encrypted key for each CA. Server-generated leaf keys can be
  downloaded once by the owner, after which their ciphertext is erased.
- The public host offers CA certificates, CRLs, OCSP, RFC 3161 timestamping, status, and exact
  fingerprint/issuer+serial lookup. It has no list or mutation endpoint for
  leaf certificates.
- Audit events are append-only, hash-chained, and partitioned by month. The
  application does not provide an audit deletion API.
- Critical JSON mutations accept an optional `Idempotency-Key` (8-128
  characters). Results are retained for 24 hours; the same key cannot be reused
  for different request content.
- Login and OCSP endpoints have application-level rate limits. Forwarded client
  addresses are used only when the direct peer belongs to `TRUSTED_PROXY_CIDRS`;
  production deployments should also enforce rate limits at Cloudflare.
- Production HTTP requests must arrive from a trusted local Tunnel connector,
  present the origin shared secret, and select one of the two configured
  hostnames before they can reach any public or Console handler.
- For Console requests, Pages transports the JWT email claim in a private
  `X-PKI-*` header because Cloudflare may remove reserved `Cf-Access-*` headers
  from subrequests. The Go gateway accepts it only after proxy, secret, and host
  checks, then the Access verifier still validates the signed JWT and all email
  values. The Function-side claim extraction does not establish trust.

## Test suites

Package tests do not require external services:

```sh
go test ./console/... ./cmd/pki-console
```

The database and full HTTP/PKI lifecycle suites are enabled explicitly against
a disposable external PostgreSQL database:

```sh
PKI_TEST_DATABASE_URL='postgres://pki_console:password@127.0.0.1:5432/pki_console?sslmode=disable' \
  go test -p 1 ./console/pki ./console/httpapi -v
```

They validate migrations, RBAC boundaries, approval separation, signing
profiles, root/intermediate/delegated-OCSP creation, client and server-generated
keys, idempotency, host separation, session/CSRF behavior, exact public lookup,
CRL, OCSP, RFC 3161/OpenSSL interoperability, revocation, one-time key erasure,
and audit-chain persistence.

The frontend quality gate includes ESLint, strict TypeScript, Vitest and a
production Vite build:

```sh
cd web
npm run check
```

Playwright covers both host surfaces, protected and role-restricted Console
routes, all primary workspaces, and desktop/mobile layouts. It uses an installed
Google Chrome browser:

```sh
cd web
npm run test:e2e
```

The API contract is [openapi.yaml](openapi.yaml). Desktop and native-client
authentication requirements are documented in
[desktop-client-integration.md](desktop-client-integration.md).

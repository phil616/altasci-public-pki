# PKI-Console

PKI-Console is an authenticated enterprise PKI control plane and React user
interface built directly on the CFSSL Go packages in this fork. It does not
execute CFSSL binaries and does not register the legacy unauthenticated
`/api/v1/cfssl/*` handlers.

For the complete Cloudflare Pages, external PostgreSQL, Cloudflare Tunnel and
systemd production procedure, see [production-deployment.md](production-deployment.md).
For tag-driven GitHub Releases and Wrangler deployment, see
[github-actions-release.md](github-actions-release.md).

## Native binary deployment

PKI-Console is distributed as a statically linked Go binary. It does not ship
or start a database, container, or embedded persistence layer. All persistent
state is stored in the external PostgreSQL instance named by `DATABASE_URL`.
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
committed lock file, and the production output contains static files only:

```sh
cd web
npm ci
npm run check
cd ..

# Or build the backend and frontend together.
make pki-console-system
```

Install `web/dist` on the reverse-proxy host. Node.js is not required at
runtime:

```sh
install -d -o root -g root -m 0755 /var/www/pki-console
cp -a web/dist/. /var/www/pki-console/
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

Production must terminate HTTPS at a trusted proxy, serve the same static build
on `pki.example.com` and `pki-console.example.com`, and proxy only the REST,
AIA, CRL and OCSP paths to the Go process while preserving the `Host` header.
Protect only the Console hostname with Cloudflare Access. A complete two-host
Nginx example is provided in `doc/pki-console/nginx.conf.example`.

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
| `DATABASE_URL` | External PostgreSQL URL; production should use `sslmode=verify-full` and a trusted CA |
| `PUBLIC_BASE_URL` | Public AIA, CRL, OCSP and exact-lookup origin |
| `CONSOLE_BASE_URL` | Authenticated Console origin |
| `ROOT_USER_EMAIL` | Unique super-administrator email |
| `ROOT_USER_PASSWORD` | Root password, at least 32 characters |
| `ROOT_USER_TOTP_SECRET` | Unpadded Base32 secret, at least 160 bits |
| `CF_ACCESS_TEAM_DOMAIN` | `https://<team>.cloudflareaccess.com` issuer |
| `CF_ACCESS_AUD` | Access application audience tag |
| `PKI_MASTER_KEY_ACTIVE_ID` | ID used for new AES-256-GCM envelopes |
| `PKI_MASTER_KEYS` | JSON map from key ID to Base64 32-byte KEK |

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
- The public host offers CA certificates, CRLs, OCSP, status, and exact
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
CRL, OCSP, revocation, one-time key erasure, and audit-chain persistence.

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

The API contract is [openapi.yaml](openapi.yaml).

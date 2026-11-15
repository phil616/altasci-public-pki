# PKI-Console

This fork adds the PKI-Console enterprise control plane under `cmd/pki-console`
and `console/`, with its React UI under `web/`. The application is distributed as
one Go binary containing the frontend, API, local username/password authentication,
and issuance worker. Nginx provides the reverse proxy and HTTPS; externally
managed PostgreSQL 18+ provides persistence. No Cloudflare service is required.

```sh
make pki-console
# Load the environment described in .env.example, then:
./bin/pki-console migrate
./bin/pki-console serve
```

An [independent CSR signing tool](doc/pki-console/independent-signing.md) supports
user-supplied CAs and scoped bearer credentials without sharing managed PKI records.

Start with [the application guide](doc/pki-console/README.md) and
[production deployment](doc/pki-console/production-deployment.md).
A complete [Nginx example](doc/pki-console/nginx.conf.example) and
[systemd unit](doc/pki-console/pki-console.service) are included.
The [OpenAPI contract](doc/pki-console/openapi.yaml) and
[desktop client guide](doc/pki-console/desktop-client-integration.md) describe
local session authentication. Earlier Cloudflare deployment and incident
records are retained in [the historical archive](doc/pki-console/archive/cloudflare-2026/README.md).
See [build and release](doc/pki-console/release.md) and
[documentation maintenance](doc/pki-console/documentation-maintenance.md) for current checks.


The first stable release uses a single [initial schema](console/store/schema.sql)
for a fresh PostgreSQL database. Numbered pre-release migrations and in-place
upgrades from pre-release databases are not supported. See
[database initialization](doc/pki-console/schema-initialization.md).

`make` defaults to the Console build. To prepare local release archives without
publishing anything:

```sh
make pki-console-release RELEASE_TAG=v1.0.0
```

The output directory `dist/pki-console-v1.0.0` must not already exist. It contains
Linux amd64 and arm64 archives plus `SHA256SUMS`; each archive includes the binary,
initial SQL, installation guide and deployment templates.
The inherited toolkit is documented separately in the
[CFSSL reference](doc/cfssl-toolkit.md); its legacy release targets do not publish Console.

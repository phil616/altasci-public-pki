# PKI-Console web

Status: current guide. Verified against source on 2026-11-15.

The web application is a React 19 single-page application shared by the two
PKI-Console hostnames:

- `CONSOLE_BASE_URL` selects the authenticated management Console.
- `PUBLIC_BASE_URL` selects the public CA, CRL and exact certificate lookup UI.

`make pki-console` builds this app and embeds `web/dist` into the Go binary.
Production needs no Node.js or separate frontend hosting. The Go server injects
the surface into an HTML meta tag for each configured hostname.

The build uses TypeScript, Vite, React Router, TanStack Query and Ant Design.
It talks only to same-origin paths, sends the HTTP-only session cookie with
requests, keeps the CSRF token in browser local storage (or memory if storage is
blocked), and adds a fresh idempotency key to retry-sensitive mutations. With
storage blocked, reloading requires a fresh login because `/auth/session` does
not reissue a CSRF token. Login confirms the cookie through `/auth/session`
before showing the console. All account roles sign in with a username/email and password.

From this directory (versions come from `package.json` and `package-lock.json`):

```sh
npm ci
npm run dev
npm run check
npm run test:e2e
```

The end-to-end suite starts Vite automatically and runs against installed
Google Chrome in desktop and mobile viewports. The API is mocked at the browser
boundary, so it does not need PostgreSQL; use the repository integration-test
instructions to validate the real API and database lifecycle.

Use `VITE_PKI_SURFACE=console` or `VITE_PKI_SURFACE=public` only when a preview
hostname cannot identify the surface automatically. Production always uses the surface selected by the Go server.

For development, start the backend on port 8080 with
`PKI_DEVELOPMENT_INSECURE=true`, `CONSOLE_BASE_URL=http://pki-console.localhost:5173`
and `PUBLIC_BASE_URL=http://pki.localhost:5173`, plus all required credentials and database
configuration. Vite serves port 5173 and proxies API/publication paths while preserving Host.
Use the configured hostname to open the appropriate surface. Development still requires
password and CSRF. See [application setup](../doc/pki-console/README.md).

`npm run build` builds static files only. `npm run preview` serves port 4173 without
an API proxy; it is a static preview, not a working production deployment.
For real API/database tests, follow the [isolated integration test instructions](../doc/pki-console/README.md#开发与测试).
Documentation checks and update rules are in [documentation maintenance](../doc/pki-console/documentation-maintenance.md).

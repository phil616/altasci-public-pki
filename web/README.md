# PKI-Console web

The web application is a React 19 single-page application shared by the two
PKI-Console hostnames:

- `CONSOLE_BASE_URL` selects the authenticated management Console.
- `PUBLIC_BASE_URL` selects the public CA, CRL and exact certificate lookup UI.

`make pki-console` builds this app and embeds `web/dist` into the Go binary.
Production needs no Node.js or separate frontend hosting. The Go server injects
the surface into an HTML meta tag for each configured hostname.

The build uses TypeScript, Vite, React Router, TanStack Query and Ant Design.
It talks only to same-origin paths, sends the HTTP-only session cookie with
requests, keeps the CSRF token in browser local storage, and adds a fresh
idempotency key to retry-sensitive mutations.

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

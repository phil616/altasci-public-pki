import { accessEmailClaim } from '../src/lib/access-jwt';

interface Env {
  PKI_ORIGIN_URL: string;
  PKI_ORIGIN_SHARED_SECRET: string;
  PKI_PUBLIC_HOST: string;
  PKI_CONSOLE_HOST: string;
}

const backendPrefixes = ['/api', '/pki', '/issuers', '/crl', '/ocsp', '/health'];

function isBackendPath(pathname: string): boolean {
  return backendPrefixes.some((prefix) => pathname === prefix || pathname.startsWith(`${prefix}/`));
}

function problem(status: number, detail: string): Response {
  return Response.json({ status, detail }, {
    status,
    headers: { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' },
  });
}

export const onRequest: PagesFunction<Env> = async ({ request, env }) => {
  const incoming = new URL(request.url);
  const hostname = incoming.hostname.toLowerCase();
  const publicHost = env.PKI_PUBLIC_HOST?.trim().toLowerCase();
  const consoleHost = env.PKI_CONSOLE_HOST?.trim().toLowerCase();

  if (!publicHost || !consoleHost || !env.PKI_ORIGIN_URL || !env.PKI_ORIGIN_SHARED_SECRET) {
    return problem(500, 'Pages Function is not configured');
  }
  if (hostname !== publicHost && hostname !== consoleHost) {
    return problem(421, 'Unknown application host');
  }
  if (!isBackendPath(incoming.pathname)) {
    return problem(404, 'Not found');
  }

  let origin: URL;
  try {
    origin = new URL(env.PKI_ORIGIN_URL);
  } catch {
    return problem(500, 'Invalid origin configuration');
  }
  if (
    origin.protocol !== 'https:'
    || origin.username
    || origin.password
    || origin.pathname !== '/'
    || origin.search
    || origin.hash
  ) {
    return problem(500, 'Invalid origin configuration');
  }

  const upstream = new URL(incoming.pathname + incoming.search, origin);
  const clientIP = request.headers.get('CF-Connecting-IP');
  const headers = new Headers(request.headers);

  for (const name of [
    'host',
    'content-length',
    'cf-access-authenticated-user-email',
    'cf-connecting-ip',
    'forwarded',
    'x-forwarded-for',
    'x-forwarded-host',
    'x-forwarded-proto',
    'x-pki-origin-secret',
    'x-pki-forwarded-host',
    'x-pki-client-ip',
    'x-pki-access-authenticated-user-email',
  ]) {
    headers.delete(name);
  }
  headers.set('X-PKI-Origin-Secret', env.PKI_ORIGIN_SHARED_SECRET);
  headers.set('X-PKI-Forwarded-Host', hostname);
  if (clientIP) headers.set('X-PKI-Client-IP', clientIP);

  // Public endpoints never need Console session or Access credentials.
  if (hostname === publicHost) {
    headers.delete('authorization');
    headers.delete('cf-access-jwt-assertion');
    headers.delete('cookie');
  } else {
    const email = accessEmailClaim(headers.get('cf-access-jwt-assertion'));
    if (!email) return problem(401, 'Cloudflare Access identity is unavailable');
    // Cloudflare may remove reserved Cf-Access-* headers on the subrequest to
    // an origin without its own Access application. Carry the untrusted JWT
    // claim over our authenticated origin channel; Go restores the official
    // header and still performs the complete JWT verification.
    headers.set('X-PKI-Access-Authenticated-User-Email', email);
  }

  const init: RequestInit = { method: request.method, headers, redirect: 'manual' };
  if (request.method !== 'GET' && request.method !== 'HEAD') init.body = request.body;

  let response: Response;
  try {
    response = await fetch(upstream.toString(), init);
  } catch {
    return problem(502, 'PKI origin is unavailable');
  }
  const responseHeaders = new Headers(response.headers);
  if (hostname === consoleHost) responseHeaders.set('Cache-Control', 'private, no-store');

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: responseHeaders,
  });
};

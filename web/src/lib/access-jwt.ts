const maxAccessTokenSize = 32 << 10;

// This only extracts an untrusted claim for transport to the Go verifier. The
// backend still verifies the JWT signature, issuer, audience, time bounds, and
// equality between this header, the signed claim, and ROOT_USER_EMAIL.
export function accessEmailClaim(token: string | null | undefined): string | undefined {
  if (!token || token.length > maxAccessTokenSize) return undefined;
  const parts = token.split('.');
  if (parts.length !== 3) return undefined;

  try {
    const normalized = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=');
    const bytes = Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
    const claims = JSON.parse(new TextDecoder().decode(bytes)) as { email?: unknown };
    if (typeof claims.email !== 'string') return undefined;
    const email = claims.email.trim().toLowerCase();
    return email || undefined;
  } catch {
    return undefined;
  }
}

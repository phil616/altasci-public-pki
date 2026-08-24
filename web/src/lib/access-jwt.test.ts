import { describe, expect, it } from 'vitest';

import { accessEmailClaim } from './access-jwt';

function tokenWithPayload(payload: unknown): string {
  const encoded = btoa(JSON.stringify(payload)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return `header.${encoded}.signature`;
}

describe('accessEmailClaim', () => {
  it('extracts and normalizes an email claim', () => {
    expect(accessEmailClaim(tokenWithPayload({ email: ' Phil616@163.com ' }))).toBe('phil616@163.com');
  });

  it('rejects malformed or missing claims', () => {
    expect(accessEmailClaim('not-a-jwt')).toBeUndefined();
    expect(accessEmailClaim(tokenWithPayload({ sub: 'user' }))).toBeUndefined();
  });
});

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { consoleAPI, setCSRFToken } from './api';

describe('console API security headers', () => {
  beforeEach(() => {
    const values = new Map<string, string>();
    vi.stubGlobal('localStorage', {
      getItem: (key: string) => values.get(key) ?? null,
      setItem: (key: string, value: string) => values.set(key, value),
      removeItem: (key: string) => values.delete(key),
    });
    vi.stubGlobal('window', { dispatchEvent: vi.fn() });
    vi.stubGlobal('crypto', { randomUUID: () => '11111111-1111-4111-8111-111111111111' });
  });

  afterEach(() => vi.unstubAllGlobals());

  it('adds CSRF and idempotency headers to mutations', async () => {
    setCSRFToken('csrf-value');
    const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 204 }));
    vi.stubGlobal('fetch', fetchMock);

    await consoleAPI.setUserStatus('user-id', 'disabled');

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const headers = init.headers as Headers;
    expect(headers.get('X-CSRF-Token')).toBe('csrf-value');
    expect(headers.get('Idempotency-Key')).toBe('11111111-1111-4111-8111-111111111111');
    expect(init.credentials).toBe('include');
  });

  it('never adds a CSRF token to a safe request', async () => {
    setCSRFToken('csrf-value');
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ items: [] }), { status: 200, headers: { 'Content-Type': 'application/json' } }),
    );
    vi.stubGlobal('fetch', fetchMock);

    await consoleAPI.authorities();

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect((init.headers as Headers).has('X-CSRF-Token')).toBe(false);
  });

  it('requests a server-filtered certificate inventory', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ items: [] }), { status: 200, headers: { 'Content-Type': 'application/json' } }),
    );
    vi.stubGlobal('fetch', fetchMock);

    await consoleAPI.certificateInventory('rejected');

    expect(fetchMock.mock.calls[0]?.[0]).toBe('/api/v1/certificate-inventory?status=rejected');
  });
});

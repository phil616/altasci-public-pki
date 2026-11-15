import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { consoleAPI, hasCSRFToken, setCSRFToken } from './api';

const dispatchEvent = vi.fn();

describe('console API security headers', () => {
  beforeEach(() => {
    const values = new Map<string, string>();
    vi.stubGlobal('localStorage', {
      getItem: (key: string) => values.get(key) ?? null,
      setItem: (key: string, value: string) => values.set(key, value),
      removeItem: (key: string) => values.delete(key),
    });
    dispatchEvent.mockClear();
    vi.stubGlobal('window', { dispatchEvent });
    vi.stubGlobal('crypto', { randomUUID: () => '11111111-1111-4111-8111-111111111111' });
    setCSRFToken();
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

  it('keeps login and CSRF working when browser storage is blocked', async () => {
    vi.stubGlobal('localStorage', {
      getItem: () => { throw new Error('Storage blocked'); },
      setItem: () => { throw new Error('Storage blocked'); },
      removeItem: () => { throw new Error('Storage blocked'); },
    });
    const fetchMock = vi.fn().mockResolvedValueOnce(new Response(JSON.stringify({
      user: { id: 'root-id' }, csrf_token: 'memory-token', expires_at: '2030-01-01T00:00:00Z',
    }), { status: 200 })).mockResolvedValueOnce(new Response(null, { status: 204 }));
    vi.stubGlobal('fetch', fetchMock);
    await consoleAPI.login({ login: 'root@example.test', password: 'unchanged password', totp: '123456' });
    expect(hasCSRFToken()).toBe(true);
    await consoleAPI.setUserStatus('user-id', 'disabled');
    const [, init] = fetchMock.mock.calls[1] as [string, RequestInit];
    expect((init.headers as Headers).get('X-CSRF-Token')).toBe('memory-token');
    setCSRFToken();
    expect(hasCSRFToken()).toBe(false);
  });

  it('does not turn a login challenge into an expired-session event', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({
      status: 401, code: 'second_factor_required', detail: 'TOTP required',
    }), { status: 401 })));
    await expect(consoleAPI.login({ login: 'root', password: 'password' })).rejects.toMatchObject({ code: 'second_factor_required' });
    expect(dispatchEvent).not.toHaveBeenCalled();
  });

  it('passes cancellation to session requests and ignores a cancelled 401', async () => {
    const controller = new AbortController();
    controller.abort();
    const fetchMock = vi.fn().mockResolvedValue(new Response('{}', { status: 401 }));
    vi.stubGlobal('fetch', fetchMock);
    await expect(consoleAPI.session(controller.signal)).rejects.toMatchObject({ status: 401 });
    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(init.signal).toBe(controller.signal);
    expect(dispatchEvent).not.toHaveBeenCalled();
  });

  it('requests a server-filtered certificate inventory', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ items: [] }), { status: 200, headers: { 'Content-Type': 'application/json' } }),
    );
    vi.stubGlobal('fetch', fetchMock);

    await consoleAPI.certificateInventory('rejected');

    expect(fetchMock.mock.calls[0]?.[0]).toBe('/api/v1/certificate-inventory?status=rejected');
  });

  it('normalizes nullable profile and timestamp authority lists', async () => {
    const fetchMock = vi.fn().mockImplementation(() => Promise.resolve(
      new Response(JSON.stringify({ items: null }), { status: 200, headers: { 'Content-Type': 'application/json' } }),
    ));
    vi.stubGlobal('fetch', fetchMock);

    const profiles = await consoleAPI.profiles('ca-id');
    const timestampAuthorities = await consoleAPI.timestampAuthorities('ca-id');

    expect(profiles.items).toEqual([]);
    expect(timestampAuthorities.items).toEqual([]);
  });
});

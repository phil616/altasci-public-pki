import { describe, expect, it, vi } from 'vitest';

import { handleVitePreloadError, PRELOAD_RELOAD_COOLDOWN_MS } from './preload-recovery';

function fakeStorage(initial?: string) {
  let value = initial;
  const getItem = vi.fn(() => value ?? null);
  const setItem = vi.fn((_key: string, next: string) => { value = next; });
  return {
    storage: { getItem, setItem },
    getItem,
    setItem,
  };
}

describe('Vite preload recovery', () => {
  it('reloads once when a deployment removed a lazy chunk', () => {
    const preventDefault = vi.fn();
    const event = { preventDefault } as unknown as Event;
    const { storage, setItem } = fakeStorage();
    const reload = vi.fn();

    expect(handleVitePreloadError(event, storage, reload, 10_000)).toBe(true);
    expect(preventDefault).toHaveBeenCalledOnce();
    expect(setItem).toHaveBeenCalledWith('pki-console:preload-reload-at', '10000');
    expect(reload).toHaveBeenCalledOnce();
  });

  it('does not enter a reload loop when the chunk is still unavailable', () => {
    const preventDefault = vi.fn();
    const event = { preventDefault } as unknown as Event;
    const { storage, setItem } = fakeStorage('10000');
    const reload = vi.fn();

    expect(handleVitePreloadError(event, storage, reload, 10_000 + PRELOAD_RELOAD_COOLDOWN_MS - 1)).toBe(false);
    expect(preventDefault).not.toHaveBeenCalled();
    expect(setItem).not.toHaveBeenCalled();
    expect(reload).not.toHaveBeenCalled();
  });

  it('still reloads when session storage is unavailable', () => {
    const event = { preventDefault: vi.fn() } as unknown as Event;
    const storage = {
      getItem: vi.fn(() => { throw new Error('denied'); }),
      setItem: vi.fn(() => { throw new Error('denied'); }),
    };
    const reload = vi.fn();

    expect(handleVitePreloadError(event, storage, reload, 10_000)).toBe(true);
    expect(reload).toHaveBeenCalledOnce();
  });
});

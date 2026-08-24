const RELOAD_STORAGE_KEY = 'pki-console:preload-reload-at';

export const PRELOAD_RELOAD_COOLDOWN_MS = 60_000;

type ReloadStorage = Pick<Storage, 'getItem' | 'setItem'>;

export function handleVitePreloadError(
  event: Event,
  storage: ReloadStorage | undefined,
  reload: () => void,
  now = Date.now(),
): boolean {
  let lastReloadAt: number | undefined;
  try {
    const stored = storage?.getItem(RELOAD_STORAGE_KEY);
    if (stored) lastReloadAt = Number(stored);
  } catch {
    // Storage can be unavailable in restricted browser contexts. Reloading is
    // still the safest recovery for a chunk that disappeared after a deploy.
  }

  if (
    lastReloadAt !== undefined
    && Number.isFinite(lastReloadAt)
    && Math.abs(now - lastReloadAt) < PRELOAD_RELOAD_COOLDOWN_MS
  ) {
    return false;
  }

  event.preventDefault();
  try {
    storage?.setItem(RELOAD_STORAGE_KEY, String(now));
  } catch {
    // Continue with the reload even when storage is unavailable.
  }
  reload();
  return true;
}

import { expect, test, type Page } from '@playwright/test';

const root = { id: '01912345-6789-7abc-8def-0123456789ab', username: 'root@example.test',
  email: 'root@example.test', role: 'super_admin', status: 'active' };
const password = "exact password with $! ' and spaces ";

async function loginAPI(page: Page, options: { rejectCookie?: boolean; unavailable?: boolean } = {}) {
  let authenticated = false;
  const submitted: Record<string, string>[] = [];
  await page.route('**/api/v1/**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/v1/auth/login') {
      const body = route.request().postDataJSON() as Record<string, string>;
      submitted.push(body);
      if (options.unavailable) {
        await route.fulfill({ status: 503, json: { status: 503, code: 'authentication_unavailable' } });
      } else {
        authenticated = !options.rejectCookie;
        await route.fulfill({ json: { user: root, csrf_token: 'login-csrf-token', expires_at: '2030-01-01T00:00:00Z' } });
      }
      return;
    }
    if (path === '/api/v1/auth/session') {
      await route.fulfill(authenticated ? { json: { user: root } }
        : { status: 401, json: { status: 401, code: 'authentication_required' } });
      return;
    }
    if (path === '/api/v1/version') {
      await route.fulfill({ json: { name: 'PKI-Console', version: 'test' } });
      return;
    }
    await route.fulfill({ json: { items: [] } });
  });
  return submitted;
}

async function fillCredentials(page: Page) {
  await page.goto('/login');
  await page.getByLabel('用户名或邮箱', { exact: true }).fill(root.email);
  await page.getByLabel('密码', { exact: true }).fill(password);
}

test('root signs in with only username and password', async ({ page }) => {
  const submitted = await loginAPI(page);
  await fillCredentials(page);
  await expect(page.locator('input')).toHaveCount(2);
  await page.getByRole('button', { name: '安全登录' }).click();
  await expect(page.getByRole('heading', { name: `欢迎回来，${root.username}` })).toBeVisible();
  expect(submitted).toEqual([{ login: root.email, password }]);
  await page.reload();
  await expect(page.getByRole('heading', { name: `欢迎回来，${root.username}` })).toBeVisible();
});

test('rejected session cookies do not appear as bad passwords or enter the console', async ({ page }) => {
  await loginAPI(page, { rejectCookie: true });
  await fillCredentials(page);
  await page.getByRole('button', { name: '安全登录' }).click();
  await expect(page.getByText(/浏览器未能建立会话/)).toBeVisible();
  await expect(page).toHaveURL(/\/login$/);
});

test('blocked browser storage still permits authenticated navigation', async ({ page }) => {
  await page.addInitScript(() => {
    for (const name of ['getItem', 'setItem', 'removeItem']) {
      Object.defineProperty(Storage.prototype, name, { value: () => { throw new Error('Storage blocked'); } });
    }
  });
  await loginAPI(page);
  await fillCredentials(page);
  await page.getByRole('button', { name: '安全登录' }).click();
  await expect(page.getByRole('heading', { name: `欢迎回来，${root.username}` })).toBeVisible();
});

test('authentication service failures have a distinct actionable message', async ({ page }) => {
  await loginAPI(page, { unavailable: true });
  await fillCredentials(page);
  await page.getByRole('button', { name: '安全登录' }).click();
  await expect(page.getByText(/认证服务暂时不可用/)).toBeVisible();
});

for (const [code, status, message] of [
  ['account_locked', 401, '密码正确，但账户仍在锁定期'],
] as const) {
  test(`identifies ${code} without calling it a wrong password`, async ({ page }) => {
    await loginAPI(page);
    await page.route('**/api/v1/auth/login', (route) => route.fulfill({ status, json: { code, status } }));
    await fillCredentials(page);
    await page.getByRole('button', { name: '安全登录' }).click();
    await expect(page.getByText(message, { exact: false })).toBeVisible();
    await expect(page).toHaveURL(/\/login$/);
  });
}

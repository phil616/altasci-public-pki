import { expect, test } from '@playwright/test';

const id = '01912345-6789-7abc-8def-0123456789ac';
const policy = {
  version: 1, allowed_dns_names: ['www.example.test'], allowed_ip_ranges: [],
  allowed_email_domains: [], allowed_uri_prefixes: [], allow_wildcards: false,
  extended_key_usages: ['server_auth'], default_validity_seconds: 2592000,
  max_validity_seconds: 7776000, max_sans: 32,
};
const instance = {
  id, owner_id: '01912345-6789-7abc-8def-0123456789ab', name: '独立实验室',
  certificate_pem: '-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----',
  chain_pem: '-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----',
  policy, enabled: true, not_before: '2026-01-01T00:00:00Z', not_after: '2030-01-01T00:00:00Z',
  endpoint: `https://pki.example.test/signing/${id}/issue`,
  created_at: '2026-11-15T00:00:00Z', updated_at: '2026-11-15T00:00:00Z',
};

test('ordinary user imports an isolated CA and creates a one-time displayed credential', async ({ page }) => {
  let created = false;
  let credentialCreated = false;
  const token = `ist_${'x'.repeat(43)}`;
  await page.addInitScript(() => localStorage.setItem('pki-console.csrf', 'test-csrf'));
  await page.route('**/api/v1/auth/session', (route) => route.fulfill({ json: { user: { id: instance.owner_id, username: 'ordinary-user', role: 'user', status: 'active' } } }));
  await page.route('**/api/v1/signing-instances', async (route) => {
    if (route.request().method() === 'POST') {
      const body = route.request().postDataJSON() as Record<string, unknown>;
      expect(body).not.toHaveProperty('ca_id');
      expect(body.private_key_pem).toBe('PRIVATE-TEST-MATERIAL');
      expect(body.policy).toMatchObject({ allowed_dns_names: ['www.example.test'], allow_wildcards: false });
      created = true;
      await route.fulfill({ status: 201, json: instance });
    } else await route.fulfill({ json: { items: created ? [instance] : [] } });
  });
  await page.route(`**/api/v1/signing-instances/${id}`, (route) => route.fulfill({ json: instance }));
  const credential = { id: '01912345-6789-7abc-8def-0123456789ad', instance_id: id, name: 'trusted-machine', scopes: ['issue', 'read'], policy: null, max_issuances: 1, issued_count: 0, rate_per_minute: 10, expires_at: '2030-01-01T00:00:00Z', revoked_at: null };
  await page.route(`**/api/v1/signing-instances/${id}/credentials`, async (route) => {
    if (route.request().method() === 'POST') {
      const body = route.request().postDataJSON() as Record<string, unknown>;
      expect(body.max_issuances).toBe(1);
      expect(body).not.toHaveProperty('policy');
      credentialCreated = true;
      await route.fulfill({ status: 201, json: { credential, token } });
    } else await route.fulfill({ json: { items: credentialCreated ? [credential] : [] } });
  });
  await page.route(`**/api/v1/signing-instances/${id}/certificates*`, (route) => route.fulfill({ json: { items: [], next_cursor: '' } }));
  await page.goto('/tools/signing');
  await expect(page.getByRole('heading', { name: '独立签发', exact: true })).toBeVisible();
  await page.getByRole('button', { name: '创建签发实例' }).click();
  await page.getByLabel('实例名称', { exact: true }).fill('独立实验室');
  await page.getByLabel('签发 CA 证书', { exact: true }).fill(instance.certificate_pem);
  await page.getByLabel('匹配的未加密 CA 私钥', { exact: true }).fill('PRIVATE-TEST-MATERIAL');
  await page.getByLabel('允许的 DNS 名称', { exact: true }).fill('www.example.test');
  await page.getByLabel('允许的 DNS 名称', { exact: true }).press('Enter');
  await page.getByRole('button', { name: '验证并创建' }).click();
  await expect(page).toHaveURL(new RegExp(`/tools/signing/${id}$`));
  await expect(page.getByText(instance.endpoint, { exact: true })).toBeVisible();
  await page.getByRole('button', { name: '创建凭据', exact: true }).click();
  await page.getByLabel('凭据名称（建议标注接收方）').fill('trusted-machine');
  await page.getByLabel('总签发额度', { exact: true }).fill('1');
  await page.getByRole('dialog').getByRole('button', { name: '确认创建凭据', exact: true }).click();
  const secret = page.getByRole('dialog', { name: '保存签发凭据' });
  await expect(secret.getByRole('textbox')).toHaveValue(token);
  await expect(page.evaluate(() => JSON.stringify({ ...localStorage, ...sessionStorage }))).resolves.not.toContain(token);
  await page.getByRole('button', { name: '已安全保存，关闭' }).click();
  await expect(secret).not.toBeVisible();
  await page.reload();
  await expect(page.getByRole('dialog', { name: '保存签发凭据' })).not.toBeVisible();
  await expect(page.getByText('trusted-machine', { exact: true })).toBeVisible();
  await expect(page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).resolves.toBe(true);
});

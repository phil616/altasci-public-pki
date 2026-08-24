import { expect, test, type Page } from '@playwright/test';

const rootUser = {
  id: '01912345-6789-7abc-8def-0123456789ab',
  username: 'root@example.com',
  email: 'root@example.com',
  role: 'super_admin',
  status: 'active',
};

async function mockAnonymous(page: Page) {
  await page.route('**/api/v1/auth/session', (route) => route.fulfill({
    status: 401,
    contentType: 'application/problem+json',
    body: JSON.stringify({ status: 401, code: 'authentication_required', detail: 'Authentication is required' }),
  }));
}

async function mockConsole(page: Page, user = rootUser) {
  await page.addInitScript(() => localStorage.setItem('pki-console.csrf', 'test-csrf-token'));
  await page.route('**/api/v1/auth/session', (route) => route.fulfill({ json: { user } }));
  await page.route('**/api/v1/version', (route) => route.fulfill({ json: { name: 'PKI-Console', version: 'test', cfssl_upstream: 'e429e727' } }));
  await page.route('**/api/v1/cas', (route) => route.fulfill({ json: { items: [] } }));
  await page.route('**/api/v1/certificate-requests', (route) => route.fulfill({ json: { items: [] } }));
  await page.route('**/api/v1/certificates', (route) => route.fulfill({ json: { items: [] } }));
  await page.route('**/api/v1/certificate-inventory*', (route) => route.fulfill({ json: { items: [] } }));
  await page.route('**/api/v1/users', (route) => route.fulfill({ json: { items: [user] } }));
  await page.route('**/api/v1/audit-events*', (route) => route.fulfill({ json: { items: [] } }));
}

test('renders the protected login experience', async ({ page }) => {
  await mockAnonymous(page);
  await page.goto('/login');
  await expect(page.getByRole('heading', { name: '登录控制台' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'AltasCI PKI Web管理平台' })).toBeVisible();
  await expect(page.getByRole('button', { name: '安全登录' })).toBeVisible();
});

test('renders the role-aware console dashboard', async ({ page }) => {
  await mockConsole(page);
  await page.goto('/');
  await expect(page.getByRole('heading', { name: '欢迎回来，root@example.com' })).toBeVisible();
  if ((page.viewportSize()?.width ?? 1440) < 992) {
    await page.getByRole('button', { name: '切换导航' }).click();
  }
  await expect(page.getByText('用户管理')).toBeVisible();
  await expect(page.getByText('审计日志')).toBeVisible();
});

test('renders the public repository without a session', async ({ page }) => {
  await page.route('**/pki/v1/authorities', (route) => route.fulfill({ json: { items: [] } }));
  await page.goto('http://pki.localhost:5173/');
  await expect(page.getByRole('heading', { name: /AltasCI PKI/ })).toBeVisible();
  await expect(page.getByRole('link', { name: '开始精确查询' })).toBeVisible();
  await expect(page.getByText('叶证书不可枚举。')).toBeVisible();
});

test('renders the public PKI about page', async ({ page }) => {
  await page.goto('http://pki.localhost:5173/about');
  await expect(page.getByRole('heading', { name: '关于 PKI', exact: true })).toBeVisible();
  await expect(page.getByText(/基于 Cloudflare CFSSL 源码构建/)).toBeVisible();
  await expect(page.getByRole('link', { name: /了解更多关于AltasCI PKI/ })).toHaveAttribute(
    'href',
    'https://github.com/phil616/altasci-public-pki',
  );
  await expect(page.getByRole('link', { name: /了解更多关于Cloudflare CFSSL/ })).toHaveAttribute(
    'href',
    'https://github.com/cloudflare/cfssl',
  );
});

test('renders every primary Console workspace', async ({ page }) => {
  await mockConsole(page);
  for (const [path, heading] of [
    ['/authorities', '证书机构'],
    ['/requests', '证书申请'],
    ['/certificates', '证书库'],
    ['/users', '用户管理'],
    ['/audit', '审计日志'],
    ['/utilities', 'PKI 工具'],
  ]) {
    await page.goto(path);
    await expect(page.getByRole('heading', { name: heading, exact: true })).toBeVisible();
  }
});

test('tracks request states in the certificate inventory and uses library workflow steps', async ({ page }) => {
  await mockConsole(page);
  const pending = {
    request_id: 'pending-request', certificate_id: null, owner_user_id: rootUser.id,
    requester_username: rootUser.username, issuer_ca_id: 'issuer-1', issuer_name: 'Issuing CA',
    issuer_slug: 'issuing-ca', subject: { common_name: 'pending.example.test' }, sans: ['pending.example.test'],
    workflow_status: 'pending', request_status: 'pending', submitted_at: new Date().toISOString(),
  };
  const rejected = {
    ...pending, request_id: 'rejected-request', subject: { common_name: 'rejected.example.test' },
    workflow_status: 'rejected', request_status: 'rejected', approver_id: rootUser.id,
    approver_username: rootUser.username, rejection_reason: 'SAN 不符合策略',
  };
  const issued = {
    ...pending, request_id: 'issued-request', certificate_id: 'certificate-1',
    subject: { common_name: 'issued.example.test' }, workflow_status: 'issued', request_status: 'issued',
    certificate_status: 'good', serial: '1001', issued_at: new Date().toISOString(),
  };
  await page.unroute('**/api/v1/certificate-inventory*');
  await page.route('**/api/v1/certificate-inventory*', (route) => {
    const status = new URL(route.request().url()).searchParams.get('status');
    const items = status === 'pending' ? [pending] : status === 'rejected' ? [rejected] : status === 'issued' ? [issued] : [pending, rejected, issued];
    return route.fulfill({ json: { items } });
  });
  await page.route('**/api/v1/certificate-requests/pending-request', (route) => route.fulfill({ json: {
    id: 'pending-request', requester_id: rootUser.id, ca_id: 'issuer-1', profile_id: 'profile-1',
    requested_subject: { common_name: 'pending.example.test' }, requested_sans: ['pending.example.test'],
    key_generation_mode: 'server_generated', status: 'pending', submitted_at: new Date().toISOString(),
  } }));

  await page.goto('/certificates');
  await expect(page.getByText('pending.example.test')).toBeVisible();
  await page.getByRole('tab', { name: '已拒绝' }).click();
  await expect(page.getByText('rejected.example.test')).toBeVisible();
  await expect(page.locator('.ant-table').getByText('已拒绝', { exact: true })).toBeVisible();
  if ((page.viewportSize()?.width ?? 1440) >= 992) {
    await expect(page.getByText('拒绝申请')).toBeVisible();
  }

  await page.goto('/requests/pending-request');
  await expect(page.locator('.ant-steps')).toBeVisible();
  await expect(page.locator('.ant-steps-item-icon')).toHaveCount(4);
  await expect(page.getByText('等待有权限的运维人员审批')).toBeVisible();
});

test('blocks ordinary users from privileged workspaces', async ({ page }) => {
  await mockConsole(page, { ...rootUser, username: 'requester', email: 'requester@example.com', role: 'user' });
  await page.goto('/users');
  await expect(page.getByText('无权访问', { exact: true })).toBeVisible();
  await page.goto('/audit');
  await expect(page.getByText('无权访问', { exact: true })).toBeVisible();
});

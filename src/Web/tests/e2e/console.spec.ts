import { expect, test, type Page } from '@playwright/test';

type MockState = {
  signedIn: boolean; protectedUnauthorized: boolean; savedLocales: string[]; requests?: string[];
  permissions?: string[]; sessionRemainingMs?: number; logoutFailures?: number;
};

const environments = [
  { id: 'prod', name: 'Production', canonicalDns: 'prod.example.test', defaultLocale: 'en-US', version: 7 },
  { id: 'dev', name: 'Development', canonicalDns: 'dev.example.test', defaultLocale: 'zh-TW', version: 4 },
];

function json(body: unknown, status = 200) {
  return { status, contentType: 'application/json', body: JSON.stringify(body) };
}

function rbac(environment: string) {
  const isProd = environment === 'prod';
  return {
    roles: [{ id: `${environment}-role`, name: isProd ? 'Production Administrator' : 'Development Reader', builtInKind: isProd ? 'Administrator' : 'Reader' }],
    permissions: [{ roleId: `${environment}-role`, permission: isProd ? 'directory.write' : 'directory.read' }],
    scopes: [{ id: `${environment}-scope`, kind: 1, value: isProd ? 'OU=Production' : 'OU=Development', includeDescendants: isProd }],
    assignments: [{ id: `${environment}-assignment`, principalId: isProd ? 'alice-prod' : 'bob-dev', roleId: `${environment}-role`, scopeId: `${environment}-scope` }],
    groupMappings: [],
  };
}

function audit(environment: string) {
  const isProd = environment === 'prod';
  return { items: [{ id: `${environment}-event`, action: isProd ? 'Production.Change' : 'Development.Read', result: 'Success', targetId: environment, occurredAt: '2026-09-11T12:00:00.000Z', correlationId: `${environment}-correlation`, actorId: isProd ? 'alice-prod' : 'bob-dev' }], nextCursor: null };
}

async function mockConsoleApi(page: Page, state: MockState) {
  await page.route('**/api/v1/**', async (route) => {
    const url = new URL(route.request().url());
    const path = url.pathname;
    if (path === '/api/v1/session/me') {
      if (!state.signedIn) { await route.fulfill(json({ title: 'Unauthenticated' }, 401)); return; }
      const headers = state.sessionRemainingMs ? { 'content-type': 'application/json', 'X-Session-Remaining-Ms': String(state.sessionRemainingMs) } : undefined;
      await route.fulfill({ ...json({ id: 'alice', displayName: 'Alice Admin' }), headers });
      return;
    }
    if (path === '/api/v1/session/csrf') { await route.fulfill(json({ token: 'test-csrf' })); return; }
    if (path === '/api/v1/session/windows') { state.signedIn = true; await route.fulfill({ status: 204 }); return; }
    if (path === '/api/v1/session/logout') {
      if (state.logoutFailures) { state.logoutFailures -= 1; await route.fulfill(json({ title: 'LogoutUnavailable' }, 503)); return; }
      state.signedIn = false;
      await route.fulfill({ status: 204 });
      return;
    }
    if (path === '/api/v1/session/preferences' && route.request().method() === 'GET') { await route.fulfill(json({ locale: 'en-US' })); return; }
    if (path === '/api/v1/session/preferences') {
      state.savedLocales.push(JSON.parse(route.request().postData() ?? '{}').locale);
      await route.fulfill(json({ locale: state.savedLocales.at(-1) }));
      return;
    }
    if (path === '/api/v1/environments') { await route.fulfill(json({ items: environments })); return; }
    if (path.endsWith('/directory/status')) { await route.fulfill(json({ status: 'Unconfigured', stale: true, mutationAvailable: false })); return; }
    const match = path.match(/^\/api\/v1\/environments\/(prod|dev)\/(access|rbac|audit)$/);
    if (match) {
      const [, environment, resource] = match;
      state.requests?.push(path);
      if (state.protectedUnauthorized && environment === 'dev') { await route.fulfill(json({ title: 'SessionExpired' }, 401)); return; }
      if (resource === 'access') { await route.fulfill(json({ permissions: state.permissions ?? ['RBAC.Manage', 'Audit.View'] })); return; }
      if (resource === 'rbac') { await route.fulfill(json(rbac(environment))); return; }
      await route.fulfill(json(audit(environment)));
      return;
    }
    await route.fulfill(json({ title: `Unhandled synthetic route: ${path}` }, 404));
  });
}

async function openAuthenticatedConsole(page: Page, state: MockState) {
  await page.addInitScript(() => localStorage.setItem('itmc.locale', 'en-US'));
  await mockConsoleApi(page, state);
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Environment overview' })).toBeVisible();
  await expect(page.locator('select')).toHaveValue('prod');
}

async function navigate(page: Page, hash: string) {
  await page.evaluate((nextHash) => { window.location.hash = nextHash; }, hash);
}

test('unauthenticated session shows the login UI and adapts to the project viewport', async ({ page }, testInfo) => {
  const state: MockState = { signedIn: false, protectedUnauthorized: false, savedLocales: [] };
  await page.addInitScript(() => localStorage.setItem('itmc.locale', 'en-US'));
  await mockConsoleApi(page, state);
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Sign in to IT Management' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Continue with Windows SSO' })).toBeVisible();
  await expect(page.getByLabel('Emergency account')).toBeVisible();
  await expect(page.getByRole('alert')).toHaveCount(0);
  await page.screenshot({ path: `test-results/screenshots/${testInfo.project.name}-login.png`, fullPage: true });
});

test('environment changes replace RBAC and audit content without stale cross-environment data', async ({ page }, testInfo) => {
  const state: MockState = { signedIn: true, protectedUnauthorized: false, savedLocales: [] };
  await openAuthenticatedConsole(page, state);
  await page.screenshot({ path: `test-results/screenshots/${testInfo.project.name}-overview.png`, fullPage: true });
  await navigate(page, '/access');
  await expect(page.getByText('Production Administrator')).toBeVisible();
  await page.locator('select').selectOption('dev');
  await expect(page.getByText('Development Reader')).toBeVisible();
  await expect(page.getByText('Production Administrator')).toHaveCount(0);
  await navigate(page, '/audit');
  await expect(page.getByText('Development.Read')).toBeVisible();
  await expect(page.getByText('Production.Change')).toHaveCount(0);
});

test('settings saves a locale preference and updates the rendered UI', async ({ page }) => {
  const state: MockState = { signedIn: true, protectedUnauthorized: false, savedLocales: [] };
  await openAuthenticatedConsole(page, state);
  await navigate(page, '/settings');
  await expect(page.getByRole('heading', { name: 'Personal settings' })).toBeVisible();
  await page.getByRole('button', { name: '繁體中文' }).click();
  await expect(page.getByRole('heading', { name: '個人設定' })).toBeVisible();
  await expect(page.locator('.settings-panel [role="status"]')).toContainText('偏好設定已儲存');
  await expect.poll(() => state.savedLocales).toContain('zh-TW');
});

test('a protected API 401 clears the identity and returns to login', async ({ page }) => {
  const state: MockState = { signedIn: true, protectedUnauthorized: true, savedLocales: [] };
  await openAuthenticatedConsole(page, state);
  await page.locator('select').selectOption('dev');
  await expect(page.getByRole('heading', { name: 'Sign in to IT Management' })).toBeVisible();
  await expect(page.getByText('Alice Admin')).toHaveCount(0);
});

test('logout clears the authenticated console after its CSRF-protected request', async ({ page }) => {
  const state: MockState = { signedIn: true, protectedUnauthorized: false, savedLocales: [] };
  await openAuthenticatedConsole(page, state);
  await page.getByRole('button', { name: 'Sign out' }).click();
  await expect(page.getByRole('heading', { name: 'Sign in to IT Management' })).toBeVisible();
  await expect(page.getByText('Alice Admin')).toHaveCount(0);
  expect(state.signedIn).toBeFalsy();
});

test('failed logout retains identity, reports the failure, and permits a successful retry', async ({ page }) => {
  const state: MockState = { signedIn: true, protectedUnauthorized: false, savedLocales: [], logoutFailures: 1 };
  await openAuthenticatedConsole(page, state);
  await page.getByRole('button', { name: 'Sign out' }).click();
  await expect(page.getByRole('heading', { name: 'Environment overview' })).toBeVisible();
  await expect(page.getByRole('alert')).toContainText('The server could not confirm sign-out');
  await page.getByRole('button', { name: 'Sign out' }).click();
  await expect(page.getByRole('heading', { name: 'Sign in to IT Management' })).toBeVisible();
  expect(state.signedIn).toBeFalsy();
});

test('restricted viewer does not request RBAC but retains overview and audit access', async ({ page }) => {
  const state: MockState = { signedIn: true, protectedUnauthorized: false, savedLocales: [], requests: [], permissions: ['Audit.View'] };
  await openAuthenticatedConsole(page, state);
  await expect(page.getByRole('heading', { name: 'Environment overview' })).toBeVisible();
  await expect(page.getByText('1', { exact: true }).first()).toBeVisible();
  expect(state.requests).toContain('/api/v1/environments/prod/audit');
  expect(state.requests).not.toContain('/api/v1/environments/prod/rbac');
  await navigate(page, '/audit');
  await expect(page.getByText('Production.Change')).toBeVisible();
  await navigate(page, '/access');
  await expect(page.getByRole('heading', { name: 'You do not have permission to read this data.' })).toBeVisible();
});

test('a short server session-expiration header returns the console to login', async ({ page }) => {
  const state: MockState = { signedIn: true, protectedUnauthorized: false, savedLocales: [], sessionRemainingMs: 800 };
  await openAuthenticatedConsole(page, state);
  await expect(page.getByRole('heading', { name: 'Sign in to IT Management' })).toBeVisible({ timeout: 3_000 });
});

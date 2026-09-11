import { createHash } from 'node:crypto';
import { test, expect, type Page } from '@playwright/test';

const env = '11111111-1111-1111-1111-111111111111';
const device = '22222222-2222-2222-2222-222222222222';
const owner = '33333333-3333-3333-3333-333333333333';
const generation = '44444444-4444-4444-4444-444444444444';
const planId = '55555555-5555-5555-5555-555555555555';
const basePlan = { id: planId, environmentId: env, directoryObjectId: device, requesterId: owner,
  requestId: '66666666-6666-6666-6666-666666666666', recipientKeyFingerprint: 'A'.repeat(43), planHash: 'a'.repeat(64),
  policyVersion: 1, directoryGeneration: generation, expiresAt: '2030-01-01T00:10:00Z', queriedAt: '2030-01-01T00:00:00Z',
  state: 'PendingApproval', reason: 'Synthetic registration', canApprove: false, canRequest: true };
interface State { manager?: boolean; approver?: boolean; actor?: string; locale?: 'en-US' | 'zh-TW'; failFirst?: boolean; failRead?: boolean; proposalStatus?: number;
  plan?: typeof basePlan; proposals: Record<string, unknown>[]; approvals: unknown[] }
async function open(page: Page, state: State) {
  await page.addInitScript(() => {
    localStorage.setItem('itmc.locale', 'en-US'); Date.now = () => Date.parse('2040-01-01T00:00:00Z');
    Object.defineProperty(navigator.credentials, 'get', { value: async () => {
      const response = Object.create(AuthenticatorAssertionResponse.prototype);
      for (const name of ['authenticatorData', 'clientDataJSON', 'signature']) Object.defineProperty(response, name, { value: new Uint8Array([1]).buffer });
      Object.defineProperty(response, 'userHandle', { value: null });
      const credential = Object.create(PublicKeyCredential.prototype);
      for (const [name, value] of Object.entries({ id: 'synthetic', rawId: new Uint8Array([1]).buffer, type: 'public-key', response, getClientExtensionResults: () => ({}) })) Object.defineProperty(credential, name, { value });
      return credential;
    } });
  });
  await page.route('**/api/v1/**', async route => {
    const url = new URL(route.request().url()); const path = url.pathname;
    const reply = (body: unknown, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
    if (path.endsWith('/session/me')) return reply({ id: state.actor ?? (state.approver ? '77777777-7777-7777-7777-777777777777' : owner), displayName: 'Synthetic operator' });
    if (path.endsWith('/session/preferences')) return reply({ locale: state.locale ?? 'en-US' });
    if (path.endsWith('/session/csrf')) return reply({ token: 'synthetic-csrf' });
    if (path.endsWith('/session/step-up/options')) return reply({ challenge: 'AQ', rpId: '127.0.0.1' });
    if (path.endsWith('/session/assertion')) return reply({});
    if (path === '/api/v1/environments') return reply({ items: [{ id: env, name: 'Synthetic environment', canonicalDns: 'example.test', defaultLocale: 'en-US', version: 1 }] });
    if (path.endsWith('/access')) return reply({ permissions: [] });
    if (path.endsWith('/enrollment-target')) return state.manager ? reply({ status: 'Eligible', queriedAt: basePlan.queriedAt }) : reply({}, 404);
    if (path.endsWith('/directory/status')) return reply({ status: 'Ready', stale: false, completedAt: basePlan.queriedAt, mutationAvailable: false });
    if (path.endsWith('/directory/objects')) return reply({ items: [], nextCursor: null, generation, asOf: basePlan.queriedAt });
    if (path.includes('/directory/objects/')) return reply({ item: { id: path.split('/').at(-1), kind: 'Computer', name: 'Synthetic device',
      distinguishedName: 'CN=synthetic,DC=example,DC=test', usnChanged: 42, protectionKnown: false, isProtected: false }, asOf: basePlan.queriedAt });
    if (path.endsWith('/enrollment-grant-plans')) {
      const body = route.request().postDataJSON(); state.proposals.push(body);
      if (state.proposalStatus) return reply({ title: 'StaleVersion' }, state.proposalStatus);
      state.plan ??= { ...basePlan, requestId: body.requestId, reason: body.reason,
        recipientKeyFingerprint: createHash('sha256').update(Buffer.from(body.recipientSpki, 'base64url')).digest('base64url') };
      if (state.failFirst && state.proposals.length === 1) return reply({ title: 'Unavailable' }, 503);
      return reply(state.plan, 201);
    }
    if (path.endsWith('/approval')) {
      state.approvals.push(route.request().postDataJSON());
      state.plan = { ...(state.plan ?? basePlan), state: 'Approved', canApprove: false };
      return reply(state.plan);
    }
    if (path.includes('/enrollment-grant-plans/')) return state.failRead ? reply({}, 503) : reply(state.plan ?? { ...basePlan, canApprove: !!state.approver, canRequest: !!state.manager });
    return reply({}, 404);
  });
  await page.goto(`/#/device?environment=${env}&id=${device}`);
  await page.getByRole('tab', { name: state.locale === 'zh-TW' ? '盤點' : 'Inventory', exact: true }).click();
}

test('registration request uses a browser recipient key and only the closed proposal fields', async ({ page }, info) => {
  const state: State = { manager: true, proposals: [], approvals: [] }; await open(page, state);
  const panel = page.getByRole('region', { name: 'Agent registration requests', exact: true });
  await panel.getByRole('textbox', { name: 'Registration reason' }).fill('Synthetic registration');
  await panel.getByRole('button', { name: 'Verify and request registration' }).click();
  await expect(panel).toContainText('Pending approval');
  expect(Object.keys(state.proposals[0]).sort()).toEqual(['expectedDirectoryGeneration', 'expectedEnvironmentVersion', 'reason', 'recipientSpki', 'requestId']);
  expect(state.proposals[0].expectedDirectoryGeneration).toBe(generation);
  expect(state.proposals[0].expectedEnvironmentVersion).toBe(1);
  expect(Buffer.from(state.proposals[0].recipientSpki as string, 'base64url').length).toBeLessThanOrEqual(512);
  await expect(panel).toContainText('No registration token is issued');
  await expect(panel.getByRole('button', { name: /approve|execute/i })).toHaveCount(0);
  await panel.screenshot({ path: `test-results/screenshots/${info.project.name}-enrollment-proposal.png` });
});

test('uncertain registration proposal retries identical request ID and public key', async ({ page }) => {
  const state: State = { manager: true, failFirst: true, proposals: [], approvals: [] }; await open(page, state);
  const panel = page.getByRole('region', { name: 'Agent registration requests', exact: true });
  await panel.getByRole('textbox', { name: 'Registration reason' }).fill('Synthetic retry request');
  await panel.getByRole('button', { name: 'Verify and request registration' }).click();
  await expect(panel).toContainText('The request may have been saved');
  await panel.getByRole('button', { name: 'Retry the same request' }).click();
  await expect(panel).toContainText('Pending approval'); expect(state.proposals).toHaveLength(2);
  expect(state.proposals[1]).toEqual(state.proposals[0]);
});

test('independent approver loads and approves the exact plan despite client clock skew', async ({ page }) => {
  const state: State = { approver: true, proposals: [], approvals: [] }; await open(page, state);
  const panel = page.getByRole('region', { name: 'Agent registration requests', exact: true });
  await expect(panel.getByRole('button', { name: 'Verify and request registration' })).toHaveCount(0);
  await panel.getByRole('textbox', { name: 'Registration request ID' }).fill(planId);
  await panel.getByRole('button', { name: 'Open or refresh request' }).click();
  await panel.getByRole('button', { name: 'Verify and approve registration' }).click();
  await expect(panel.getByText('Approved', { exact: true })).toBeVisible();
  expect(state.approvals).toEqual([{ planHash: basePlan.planHash }]);
});

test('failed owner refresh and same-plan recovery retain the recipient key', async ({ page }) => {
  const state: State = { manager: true, proposals: [], approvals: [] }; await open(page, state);
  const panel = page.getByRole('region', { name: 'Agent registration requests', exact: true });
  await panel.getByRole('textbox', { name: 'Registration reason' }).fill('Synthetic key retention');
  await panel.getByRole('button', { name: 'Verify and request registration' }).click();
  await expect(panel).toContainText('Pending approval'); state.failRead = true;
  await panel.getByRole('button', { name: 'Open or refresh request' }).click();
  await expect(panel.getByRole('alert')).toBeVisible();
  await expect(panel).toContainText('The recipient key is retained on this page.');
  state.failRead = false; await panel.getByRole('button', { name: 'Open or refresh request' }).click();
  await expect(panel).toContainText('Pending approval');
  await expect(panel).toContainText('The recipient key is retained on this page.');
  expect(state.proposals).toHaveLength(1);
});

test('failed refresh clears actionable approval and stale plan contents', async ({ page }) => {
  const state: State = { approver: true, proposals: [], approvals: [] }; await open(page, state);
  const panel = page.getByRole('region', { name: 'Agent registration requests', exact: true });
  await panel.getByRole('textbox', { name: 'Registration request ID' }).fill(planId);
  await panel.getByRole('button', { name: 'Open or refresh request' }).click();
  await expect(panel).toContainText(basePlan.planHash); state.failRead = true;
  await panel.getByRole('button', { name: 'Open or refresh request' }).click();
  await expect(panel.getByRole('alert')).toBeVisible(); await expect(panel).not.toContainText(basePlan.planHash);
  await expect(panel.getByRole('button', { name: 'Verify and approve registration' })).toHaveCount(0);
});

test('a plan for another directory device is not displayed or approved', async ({ page }) => {
  const state: State = { approver: true, plan: { ...basePlan, canApprove: true, directoryObjectId: '88888888-8888-8888-8888-888888888888' }, proposals: [], approvals: [] };
  await open(page, state); const panel = page.getByRole('region', { name: 'Agent registration requests', exact: true });
  await panel.getByRole('textbox', { name: 'Registration request ID' }).fill(planId);
  await panel.getByRole('button', { name: 'Open or refresh request' }).click();
  await expect(panel.getByRole('alert')).toBeVisible(); await expect(panel).not.toContainText(basePlan.planHash);
  expect(state.approvals).toEqual([]);
});

test('registration approval expires using server remaining time', async ({ page }) => {
  const state: State = { approver: true, plan: { ...basePlan, canApprove: true, expiresAt: '2030-01-01T00:00:01Z' }, proposals: [], approvals: [] };
  await open(page, state); const panel = page.getByRole('region', { name: 'Agent registration requests', exact: true });
  await panel.getByRole('textbox', { name: 'Registration request ID' }).fill(planId);
  await panel.getByRole('button', { name: 'Open or refresh request' }).click();
  await expect(panel.getByText('Expired', { exact: true })).toBeVisible();
  await expect(panel.getByRole('button', { name: 'Verify and approve registration' })).toHaveCount(0);
});

test('registration request controls follow Traditional Chinese session preference', async ({ page }) => {
  await open(page, { manager: true, locale: 'zh-TW', proposals: [], approvals: [] });
  const panel = page.getByRole('region', { name: 'Agent 註冊申請', exact: true });
  await expect(panel.getByRole('button', { name: '驗證身分並提出註冊申請' })).toBeVisible();
  await expect(panel.getByRole('textbox', { name: '註冊申請 ID' })).toBeVisible();
});

test('editing the lookup ID makes the previous registration approval non-actionable', async ({ page }) => {
  const state: State = { approver: true, proposals: [], approvals: [] }; await open(page, state);
  const panel = page.getByRole('region', { name: 'Agent registration requests', exact: true });
  await panel.getByRole('textbox', { name: 'Registration request ID' }).fill(planId);
  await panel.getByRole('button', { name: 'Open or refresh request' }).click();
  await expect(panel.getByRole('button', { name: 'Verify and approve registration' })).toBeVisible();
  await panel.getByRole('textbox', { name: 'Registration request ID' }).fill('88888888-8888-8888-8888-888888888888');
  await expect(panel).not.toContainText(basePlan.planHash);
  await expect(panel.getByRole('button', { name: 'Verify and approve registration' })).toHaveCount(0);
  expect(state.approvals).toEqual([]);
});

test('a requester loading an existing registration plan is told the local key is missing', async ({ page }) => {
  await open(page, { manager: true, proposals: [], approvals: [] });
  const panel = page.getByRole('region', { name: 'Agent registration requests', exact: true });
  await panel.getByRole('textbox', { name: 'Registration request ID' }).fill(planId);
  await panel.getByRole('button', { name: 'Open or refresh request' }).click();
  await expect(panel).toContainText('The recipient key is not available on this page.');
  await expect(panel).not.toContainText('Keep this device page open to retain the recipient key.');
});

test('unexpected private fields in a registration plan are rejected', async ({ page }) => {
  await open(page, { approver: true, plan: Object.assign({ ...basePlan, canApprove: true }, { serverDeviceId: 'PRIVATE-MAPPING-CANARY' }), proposals: [], approvals: [] });
  const panel = page.getByRole('region', { name: 'Agent registration requests', exact: true });
  await panel.getByRole('textbox', { name: 'Registration request ID' }).fill(planId);
  await panel.getByRole('button', { name: 'Open or refresh request' }).click();
  await expect(panel.getByRole('alert')).toBeVisible(); await expect(panel).not.toContainText(basePlan.planHash);
  await expect(panel).not.toContainText('PRIVATE-MAPPING-CANARY');
});

test('uncertain registration keys expire locally and a later proposal gets a new request ID and key', async ({ page }) => {
  const state: State = { manager: true, failFirst: true, proposals: [], approvals: [] }; await open(page, state);
  await page.clock.install();
  const panel = page.getByRole('region', { name: 'Agent registration requests', exact: true });
  await panel.getByRole('textbox', { name: 'Registration reason' }).fill('Synthetic expiring request');
  await panel.getByRole('button', { name: 'Verify and request registration' }).click();
  await expect(panel.getByRole('button', { name: 'Retry the same request' })).toBeVisible();
  await page.clock.fastForward(600_001);
  await expect(panel.getByRole('button', { name: 'Retry the same request' })).toHaveCount(0);
  await expect(panel).not.toContainText('The recipient key is retained on this page.');
  await expect(panel).toContainText('This request window has expired.');
  state.plan = undefined;
  await panel.getByRole('button', { name: 'Verify and request registration' }).click();
  await expect(panel).toContainText('Pending approval');
  expect(state.proposals[1].requestId).not.toBe(state.proposals[0].requestId);
  expect(state.proposals[1].recipientSpki).not.toBe(state.proposals[0].recipientSpki);
});

test('changing device clears an uncertain registration request and its local key', async ({ page }) => {
  const state: State = { manager: true, failFirst: true, proposals: [], approvals: [] }; await open(page, state);
  const panel = page.getByRole('region', { name: 'Agent registration requests', exact: true });
  await panel.getByRole('textbox', { name: 'Registration reason' }).fill('Synthetic device change');
  await panel.getByRole('button', { name: 'Verify and request registration' }).click();
  await expect(panel.getByRole('button', { name: 'Retry the same request' })).toBeVisible();
  await page.evaluate(hash => { location.hash = hash; }, `#/device?environment=${env}&id=88888888-8888-8888-8888-888888888888`);
  await page.getByRole('tab', { name: 'Inventory', exact: true }).click();
  await expect(panel.getByRole('button', { name: 'Retry the same request' })).toHaveCount(0);
  await expect(panel).not.toContainText('The recipient key is retained on this page.');
  await expect(panel.getByRole('textbox', { name: 'Registration reason' })).toHaveValue('');
  expect(state.proposals).toHaveLength(1);
});

test('a changed authenticated principal cannot reuse an uncertain registration request', async ({ page }) => {
  const state: State = { manager: true, failFirst: true, proposals: [], approvals: [] }; await open(page, state);
  const panel = page.getByRole('region', { name: 'Agent registration requests', exact: true });
  await panel.getByRole('textbox', { name: 'Registration reason' }).fill('Synthetic session change');
  await panel.getByRole('button', { name: 'Verify and request registration' }).click();
  await expect(panel.getByRole('button', { name: 'Retry the same request' })).toBeVisible();
  state.actor = '77777777-7777-7777-7777-777777777777';
  await panel.getByRole('button', { name: 'Retry the same request' }).click();
  await expect(panel).toHaveCount(0); expect(state.proposals).toHaveLength(1);
});

test('an approval response cannot replace the immutable registration plan', async ({ page }) => {
  const state: State = { approver: true, proposals: [], approvals: [] }; await open(page, state);
  const panel = page.getByRole('region', { name: 'Agent registration requests', exact: true });
  await panel.getByRole('textbox', { name: 'Registration request ID' }).fill(planId);
  await panel.getByRole('button', { name: 'Open or refresh request' }).click();
  await expect(panel.getByRole('button', { name: 'Verify and approve registration' })).toBeVisible();
  state.plan = { ...basePlan, planHash: 'b'.repeat(64) };
  await panel.getByRole('button', { name: 'Verify and approve registration' }).click();
  await expect(panel.getByRole('alert')).toBeVisible();
  await expect(panel.getByText('Approved', { exact: true })).toHaveCount(0);
  await expect(panel).not.toContainText('b'.repeat(64));
});

test('definite stale registration rejection does not offer an uncertain retry', async ({ page }) => {
  await open(page, { manager: true, proposalStatus: 412, proposals: [], approvals: [] });
  const panel = page.getByRole('region', { name: 'Agent registration requests', exact: true });
  await panel.getByRole('textbox', { name: 'Registration reason' }).fill('Synthetic stale request');
  await panel.getByRole('button', { name: 'Verify and request registration' }).click();
  await expect(panel.getByRole('alert')).toBeVisible();
  await expect(panel.getByRole('button', { name: 'Retry the same request' })).toHaveCount(0);
  await expect(panel).not.toContainText('The request may have been saved.');
  await expect(panel.getByRole('button', { name: 'Clear view and discard local key' })).toBeVisible();
});

test('expiry of an approver previous plan cannot abort another registration lookup', async ({ page }) => {
  const state: State = { approver: true, plan: { ...basePlan, canApprove: true, expiresAt: '2030-01-01T00:00:02Z' }, proposals: [], approvals: [] };
  await open(page, state); await page.clock.install();
  const panel = page.getByRole('region', { name: 'Agent registration requests', exact: true });
  await panel.getByRole('textbox', { name: 'Registration request ID' }).fill(planId);
  await panel.getByRole('button', { name: 'Open or refresh request' }).click();
  await expect(panel.getByRole('button', { name: 'Verify and approve registration' })).toBeVisible();
  const otherId = '88888888-8888-8888-8888-888888888888';
  let release!: () => void; const pending = new Promise<void>(resolve => { release = resolve; });
  let entered!: () => void; const started = new Promise<void>(resolve => { entered = resolve; });
  await page.route(`**/enrollment-grant-plans/${otherId}`, async route => {
    entered(); await pending;
    await route.fulfill({ contentType: 'application/json', body: JSON.stringify({ ...basePlan, id: otherId, canApprove: true }) });
  });
  await panel.getByRole('textbox', { name: 'Registration request ID' }).fill(otherId);
  await panel.getByRole('button', { name: 'Open or refresh request' }).click(); await started;
  await page.clock.fastForward(3_000); release();
  await expect(panel.getByRole('button', { name: 'Verify and approve registration' })).toBeVisible();
  await expect(panel.getByRole('alert')).toHaveCount(0);
  await expect(panel).not.toContainText('local key was discarded');
});

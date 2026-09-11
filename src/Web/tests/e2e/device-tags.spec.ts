import { test, expect, type Page } from '@playwright/test';

const env = '11111111-1111-1111-1111-111111111111';
const tagId = '22222222-2222-2222-2222-222222222222';
const device = '33333333-3333-3333-3333-333333333333';
const queriedAt = '2030-01-01T00:00:00Z';
const tag = { id: tagId, key: 'VIP', version: 1, archivedAt: null };
const basePlan = { id: '44444444-4444-4444-4444-444444444444', requesterId: 'owner', action: 'device-tag.assign',
  change: { kind: 'device-tag.assign', tagId, objectId: device, expectedTagVersion: 1 }, planHash: 'a'.repeat(64), policyVersion: 1,
  expiresAt: '2030-01-01T00:15:00Z', state: 'PendingApproval', reason: 'Synthetic classification' };
interface State { manager?: boolean; approver?: boolean; actor?: string; plans?: typeof basePlan[]; fail?: boolean; actions: { path: string; body: unknown }[]; filters: string[] }
async function setup(page: Page, state: State) {
  await page.addInitScript(() => {
    localStorage.setItem('itmc.locale', 'en-US');
    Date.now = () => Date.parse('2031-01-01T00:00:00Z'); // Deliberate client/server clock skew.
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
    if (path.endsWith('/session/me')) return reply({ id: state.actor ?? 'owner', displayName: 'Synthetic operator' });
    if (path.endsWith('/session/preferences')) return reply({ locale: 'en-US' });
    if (path.endsWith('/session/csrf')) return reply({ token: 'synthetic-csrf' });
    if (path.endsWith('/session/step-up/options')) { state.actions.push({ path, body: {} }); return reply({ challenge: 'AQ', rpId: '127.0.0.1' }); }
    if (path.endsWith('/session/assertion')) return reply({});
    if (path === '/api/v1/environments') return reply({ items: [{ id: env, name: 'Synthetic environment', canonicalDns: 'example.test', defaultLocale: 'en-US', version: 1 }] });
    if (path.endsWith('/access')) return reply({ permissions: [] });
    if (path.endsWith('/device-tags/plans')) return reply({ items: state.plans ?? [], queriedAt });
    if (path.endsWith('/device-tags')) return state.fail ? reply({ title: 'Unavailable' }, 503) : reply({ items: [tag], version: 1, canManage: !!state.manager, canApprove: !!state.approver });
    if (path.endsWith('/tags')) return reply({ items: [tag] });
    if (path.includes('/change-plans')) {
      const body = route.request().postDataJSON(); state.actions.push({ path, body });
      if (path.endsWith('/approval')) { state.plans = [{ ...basePlan, state: 'Approved' }]; return reply(state.plans[0]); }
      if (path.endsWith('/execution')) { state.plans = [{ ...basePlan, state: 'Executed' }]; return reply({ state: 'Executed' }); }
      state.plans = [{ ...basePlan, action: body.change.kind, change: body.change, reason: body.reason }]; return reply(state.plans[0], 201);
    }
    if (path.endsWith('/directory/status')) return reply({ status: 'Ready', stale: false, completedAt: queriedAt, mutationAvailable: false });
    if (path.endsWith('/directory/objects')) { state.filters.push(url.searchParams.get('tagId') ?? ''); return reply({ items: [], nextCursor: null, generation: 'synthetic', asOf: queriedAt }); }
    return reply({ title: 'NotFound' }, 404);
  });
}

test('tag catalog proposal stays in platform and uses step-up before immutable plan', async ({ page }) => {
  const state: State = { manager: true, actions: [], filters: [] }; await setup(page, state); await page.goto('/#/tags');
  const panel = page.getByRole('region', { name: 'Device tags', exact: true });
  await panel.getByText('Manage tags and assignments', { exact: true }).click();
  await expect(panel.getByRole('button', { name: 'Propose creation' }).first()).toBeDisabled();
  await panel.getByRole('textbox', { name: 'Reason' }).fill('Synthetic classification');
  await panel.getByRole('button', { name: 'Propose creation' }).first().click();
  await expect(panel).toContainText('The change was accepted');
  expect(state.actions.map(value => value.path)).toEqual(['/api/v1/session/step-up/options', `/api/v1/environments/${env}/change-plans`]);
  expect(state.actions[1].body).toEqual({ change: { kind: 'device-tag.create', tagKey: 'Finance' }, expectedVersion: 1, reason: 'Synthetic classification' });
  await panel.getByText('Environment tag change plans', { exact: true }).click();
  await expect(panel).toContainText('Pending approval'); await expect(panel.getByRole('button', { name: 'Verify and execute' })).toHaveCount(0);
});

test('approver can review and approve without device view despite client clock skew', async ({ page }, info) => {
  const state: State = { approver: true, actor: 'reviewer', plans: [basePlan], actions: [], filters: [] };
  await setup(page, state); await page.goto('/#/tags');
  const panel = page.getByRole('region', { name: 'Device tags', exact: true });
  await expect(panel.getByText('Manage tags and assignments', { exact: true })).toHaveCount(0);
  await panel.getByText('Environment tag change plans', { exact: true }).click();
  await expect(panel).toContainText(device); await expect(panel).toContainText(basePlan.planHash);
  await panel.getByRole('button', { name: 'Verify and approve' }).click();
  await expect(panel).toContainText('Approved');
  expect(state.actions[1].body).toEqual({ planHash: basePlan.planHash });
  await expect(panel.getByRole('button', { name: 'Verify and execute' })).toHaveCount(0);
  await panel.getByText('Environment tag change plans', { exact: true }).click();
  await expect(panel.getByText('Approved', { exact: true })).toBeVisible();
  await panel.screenshot({ path: `test-results/screenshots/${info.project.name}-device-tags.png` });
});

test('requester execution and failed refresh clear actionable plans', async ({ page }) => {
  const state: State = { manager: true, plans: [{ ...basePlan, state: 'Approved' }], actions: [], filters: [] };
  await setup(page, state); await page.goto('/#/tags');
  const panel = page.getByRole('region', { name: 'Device tags', exact: true });
  await panel.getByText('Environment tag change plans', { exact: true }).click();
  await panel.getByRole('button', { name: 'Verify and execute' }).click();
  await expect(panel).toContainText('Executed'); expect(state.actions[1].path.endsWith('/execution')).toBe(true);
  state.fail = true; await panel.getByRole('button', { name: 'Refresh tags' }).click();
  await expect(panel.getByRole('alert')).toContainText('Tags are unavailable');
  await expect(panel).not.toContainText(basePlan.planHash);
});

test('device tag filter is sent to scoped directory endpoint', async ({ page }) => {
  const state: State = { actions: [], filters: [] }; await setup(page, state); await page.goto('/#/computers');
  await page.getByRole('combobox', { name: 'Device tag', exact: true }).selectOption(tagId);
  await expect.poll(() => state.filters).toEqual(['', tagId]);
});

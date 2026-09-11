import { test, expect, type Page } from '@playwright/test';

const env = '11111111-1111-1111-1111-111111111111';
const other = '99999999-9999-9999-9999-999999999999';
const tagId = '22222222-2222-2222-2222-222222222222';
const id = '33333333-3333-3333-3333-333333333333';
const asOf = '2026-09-11T19:00:00Z';
const initial = { id, schemaVersion: 1, name: 'Finance computers', kind: 'Computer', search: 'finance', tagId, version: 1, createdAt: asOf, updatedAt: asOf };
interface State { items: typeof initial[]; drift?: boolean; fail?: boolean; expired?: boolean; delay?: boolean; resultCalls: number; actions: { method: string; body: unknown; version?: string }[] }
async function setup(page: Page, state: State) {
  await page.addInitScript(() => localStorage.setItem('itmc.locale', 'en-US'));
  await page.route('**/api/v1/**', async route => {
    const url = new URL(route.request().url()); const path = url.pathname;
    const reply = (body: unknown, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
    if (path.endsWith('/session/me')) return reply({ id: 'synthetic-user', displayName: 'Synthetic operator' });
    if (path.endsWith('/session/preferences')) return reply({ locale: 'en-US' });
    if (path.endsWith('/session/csrf')) return reply({ token: 'synthetic' });
    if (path === '/api/v1/environments') return reply({ items: [env, other].map((id, i) => ({ id, name: i === 0 ? 'East' : 'West', canonicalDns: 'example.test', defaultLocale: 'en-US', version: 1 })) });
    if (path.endsWith('/access')) return reply({ permissions: [] });
    if (path.endsWith('/device-tags')) return reply({ items: [{ id: tagId, key: 'Finance', archivedAt: null }] });
    if (path.endsWith('/directory/status')) return reply({ status: 'Ready', stale: false, completedAt: asOf, mutationAvailable: false });
    if (path.endsWith('/results')) {
      state.resultCalls++;
      if (state.expired) return reply({ title: 'SessionInvalid' }, 401);
      if (state.drift) return reply({ title: 'SavedFilterChanged' }, 409);
      expect(url.searchParams.get('filterVersion')).toBe('1');
      if (state.delay) await new Promise(resolve => setTimeout(resolve, 500));
      return reply({ items: [{ id: '44444444-4444-4444-4444-444444444444', kind: 'Computer', name: 'Synthetic finance PC', distinguishedName: 'CN=synthetic,DC=test', protectionKnown: false, isProtected: false, usnChanged: 1 }], nextCursor: null, generation: 'synthetic', asOf });
    }
    if (path.includes('/saved-filters')) {
      const method = route.request().method();
      if (method === 'GET') return reply({ items: path.includes(other) ? [] : state.items });
      const body = method === 'DELETE' ? null : route.request().postDataJSON();
      state.actions.push({ method, body, version: route.request().headers()['if-match'] });
      if (state.fail) return reply({ title: 'StaleVersion' }, 412);
      if (method === 'POST') { const value = { ...initial, ...body, id: '55555555-5555-5555-5555-555555555555' }; state.items.push(value); return reply(value, 201); }
      if (method === 'PUT') { const value = { ...initial, ...body, version: 2 }; state.items[0] = value; return reply(value); }
      state.items = state.items.filter(item => !path.endsWith(item.id)); return route.fulfill({ status: 204 });
    }
    return reply({ title: 'UnexpectedRoute' }, 404);
  });
  await page.goto('/#/filters');
}
const state = (): State => ({ items: [{ ...initial }], actions: [], resultCalls: 0 });

test('personal filter create edit and removal preserve closed definitions and versions', async ({ page }) => {
  const data = state(); await setup(page, data);
  const root = page.getByRole('region', { name: 'Saved filters', exact: true });
  const form = root.getByRole('form', { name: 'New saved filter' });
  await form.getByLabel('Filter name').fill('Shared search'); await form.getByLabel('Search text').fill('shared');
  await form.getByRole('button', { name: 'Save filter', exact: true }).click();
  await expect(root).toContainText('2 of 50 saved');
  expect(data.actions[0].body).toEqual({ schemaVersion: 1, name: 'Shared search', kind: 'Computer', search: 'shared', tagId: null });
  const original = root.getByRole('listitem').filter({ has: page.getByRole('heading', { name: initial.name, exact: true }) });
  await original.getByRole('button', { name: 'Edit filter' }).click();
  const edit = root.getByRole('form', { name: 'Edit saved filter' });
  await edit.getByLabel('Filter name').fill('Finance renamed'); await edit.getByRole('button', { name: 'Save changes' }).click();
  await expect(root).toContainText('Finance renamed'); expect(data.actions[1].version).toBe('"1"');
  const renamed = root.getByRole('listitem').filter({ has: page.getByRole('heading', { name: 'Finance renamed' }) });
  await renamed.getByRole('button', { name: 'Remove filter' }).click(); expect(data.actions).toHaveLength(2);
  await root.getByRole('button', { name: 'Confirm filter removal', exact: true }).click();
  await expect(root).toContainText('1 of 50 saved'); expect(data.actions[2].version).toBe('"2"');
});

test('saved filter runs authorized result endpoint and changed definition stops retries', async ({ page }, info) => {
  const data = state(); await setup(page, data); await page.getByRole('button', { name: 'Run filter' }).click();
  const results = page.getByRole('region', { name: 'Filter results', exact: true });
  await expect(results).toContainText('Synthetic finance PC'); expect(data.resultCalls).toBe(1);
  await results.screenshot({ path: `test-results/screenshots/${info.project.name}-saved-filter-results.png` });
  await page.getByRole('button', { name: 'Run filter' }).click();
  await expect.poll(() => data.resultCalls).toBe(2);
  data.drift = true; await results.getByRole('button', { name: 'Refresh directory', exact: true }).click();
  await expect(results).toContainText('This saved filter changed elsewhere'); await expect(results).not.toContainText('Synthetic finance PC');
  expect(data.resultCalls).toBe(3);
});

test('stale edit clears results and requires explicit refresh', async ({ page }) => {
  const data = state(); await setup(page, data); await page.getByRole('button', { name: 'Run filter' }).click();
  await expect(page.getByRole('region', { name: 'Filter results' })).toContainText('Synthetic finance PC');
  await page.getByRole('button', { name: 'Edit filter' }).click(); data.fail = true;
  await page.getByRole('button', { name: 'Save changes' }).click();
  await expect(page.getByRole('alert')).toContainText('Refresh before retrying');
  await expect(page.getByRole('region', { name: 'Filter results' })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Run filter' })).toHaveCount(0);
});

test('late saved-filter results cannot cross environment switch', async ({ page }) => {
  const data = state(); data.delay = true; await setup(page, data);
  await page.getByRole('button', { name: 'Run filter' }).click(); await expect.poll(() => data.resultCalls).toBe(1);
  await page.locator('.environment-picker select').selectOption(other);
  await expect(page.getByRole('region', { name: 'Saved filters', exact: true })).toContainText('No saved filters yet');
  await page.waitForTimeout(600); await expect(page.getByText('Synthetic finance PC')).toHaveCount(0);
});

test('expired saved-filter execution clears the console', async ({ page }) => {
  const data = state(); data.expired = true; await setup(page, data);
  await page.getByRole('button', { name: 'Run filter' }).click();
  await expect(page.getByRole('region', { name: 'Saved filters', exact: true })).toHaveCount(0);
  await expect(page.getByText('Synthetic finance PC')).toHaveCount(0);
});

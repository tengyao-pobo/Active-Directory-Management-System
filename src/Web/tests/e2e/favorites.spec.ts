import { test, expect, type Page } from '@playwright/test';

interface State { saved: Set<string>; unavailable?: boolean; limit?: boolean; expired?: boolean }
const asOf = '2026-09-11T17:00:00Z';
const object = (env: string, kind: string) => ({ id: `${env}-${kind}`, kind, name: `${env} ${kind} favorite`,
  distinguishedName: `CN=synthetic-${kind},DC=${env},DC=test`, department: 'Operations', usnChanged: 1, protectionKnown: false, isProtected: false });
async function mock(page: Page, state: State) {
  await page.addInitScript(() => localStorage.setItem('itmc.locale', 'en-US'));
  await page.route('**/api/v1/**', async route => {
    const url = new URL(route.request().url()); const path = url.pathname; const method = route.request().method();
    const reply = (body: unknown, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
    if (path.endsWith('/session/me')) return reply({ id: 'synthetic-reader', displayName: 'Reader' });
    if (path.endsWith('/session/preferences')) return reply({ locale: 'en-US' });
    if (path.endsWith('/session/csrf')) return reply({ token: 'synthetic-csrf' });
    if (path === '/api/v1/environments') return reply({ items: ['east', 'west'].map(id => ({ id, name: `${id} environment`, canonicalDns: `${id}.test`, defaultLocale: 'en-US', version: 1 })) });
    if (path.endsWith('/access')) return reply({ permissions: [] });
    if (state.expired) return reply({ title: 'SessionInvalid' }, 401);
    if (path.endsWith('/directory/status')) return reply({ status: 'Ready', stale: false, completedAt: asOf, mutationAvailable: false });
    const env = path.includes('/west/') ? 'west' : 'east';
    if (path.endsWith('/directory/objects')) return reply({ items: [object(env, url.searchParams.get('kind') ?? 'User')], nextCursor: null, generation: env, asOf });
    if (path.includes('/directory/objects/')) return reply({ item: object(env, path.split('/').at(-1)!.split('-')[1]), asOf });
    if (path.endsWith('/favorites')) {
      if (state.unavailable) return reply({ title: 'DirectoryUnavailable' }, 503);
      return reply({ items: ['Computer', 'User', 'Group', 'OrganizationalUnit'].filter(kind => state.saved.has(`${env}-${kind}`)).map(kind => object(env, kind)), nextCursor: null, generation: env, asOf });
    }
    if (path.includes('/favorites/')) {
      const id = path.split('/').at(-1)!;
      if (method === 'GET') return reply({ saved: state.saved.has(id) });
      expect(route.request().headers()['x-csrf-token']).toBe('synthetic-csrf');
      if (state.limit && method === 'PUT') return reply({ title: 'FavoritesLimitReached' }, 409);
      if (method === 'PUT') state.saved.add(id); else if (method === 'DELETE') state.saved.delete(id);
      return route.fulfill({ status: 204 });
    }
    if (path.match(/\/devices\/.+\/user$/)) return reply({ user: null, version: 0, canEdit: false });
    if (path.match(/\/users\/.+\/devices$/)) return reply({ items: [], nextCursor: null });
    return reply({ title: 'NotFound' }, 404);
  });
}

for (const [view, kind] of [['computers', 'Computer'], ['users', 'User'], ['groups', 'Group'], ['ou', 'OrganizationalUnit']]) {
  test(`${kind} can be saved from platform details and removed from favorites`, async ({ page }, info) => {
    const state: State = { saved: new Set() }; await mock(page, state); await page.goto(`/#/${view}`);
    await page.getByRole('button', { name: new RegExp(`east ${kind} favorite`) }).click();
    await page.getByRole('button', { name: 'Add to favorites', exact: true }).click();
    await expect(page.getByRole('button', { name: 'Remove from favorites', exact: true })).toBeVisible();
    await page.goto('/#/favorites'); await page.getByRole('button', { name: new RegExp(`east ${kind} favorite`) }).click();
    await expect(page.getByRole('heading', { name: `east ${kind} favorite`, exact: true })).toBeVisible();
    if (kind === 'Computer') await page.screenshot({ path: `test-results/screenshots/${info.project.name}-favorites.png`, fullPage: true });
    await page.getByRole('button', { name: 'Remove from favorites', exact: true }).click();
    await expect(page.getByText('No visible favorites. Add objects from their details.')).toBeVisible();
    expect(state.saved.size).toBe(0);
  });
}

test('favorites errors are distinct from empty results and expiry clears the console', async ({ page }) => {
  const state: State = { saved: new Set(['east-User']), unavailable: true }; await mock(page, state); await page.goto('/#/favorites');
  await expect(page.getByRole('alert')).toContainText('Favorites unavailable');
  await expect(page.getByText('No visible favorites. Add objects from their details.')).toHaveCount(0);
  state.unavailable = false; await page.getByRole('button', { name: 'Refresh favorites', exact: true }).click();
  await expect(page.getByRole('button', { name: /east User favorite/ })).toBeVisible();
  state.expired = true; await page.getByRole('button', { name: 'Refresh favorites', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Sign in to IT Management' })).toBeVisible();
  await expect(page.getByText('east User favorite')).toHaveCount(0);
});

test('capacity failure preserves unsaved state', async ({ page }) => {
  const state: State = { saved: new Set(), limit: true }; await mock(page, state); await page.goto('/#/groups');
  await page.getByRole('button', { name: /east Group favorite/ }).click();
  await page.getByRole('button', { name: 'Add to favorites', exact: true }).click();
  await expect(page.getByRole('alert')).toContainText('500 favorites');
  await expect(page.getByRole('button', { name: 'Add to favorites', exact: true })).toBeEnabled();
  expect(state.saved.size).toBe(0);
});

test('favorites pagination clears detail and snapshot changes require refresh', async ({ page }) => {
  const state: State = { saved: new Set(['east-Computer', 'east-User']) }; await mock(page, state);
  let drift = false;
  await page.route('**/favorites?*', async route => {
    const second = new URL(route.request().url()).searchParams.has('cursor');
    if (second && drift) return route.fulfill({ status: 409, contentType: 'application/json', body: JSON.stringify({ title: 'DirectorySnapshotChanged' }) });
    return route.fulfill({ contentType: 'application/json', body: JSON.stringify({ items: [object('east', second ? 'User' : 'Computer')], nextCursor: second ? null : 'next+cursor/=', generation: 'east', asOf }) });
  });
  await page.goto('/#/favorites'); await page.getByRole('button', { name: /east Computer favorite/ }).click();
  await expect(page.getByRole('heading', { name: 'east Computer favorite', exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Next', exact: true }).click();
  await expect(page.getByRole('button', { name: /east User favorite/ })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'east Computer favorite', exact: true })).toHaveCount(0);
  await page.getByRole('button', { name: 'First page', exact: true }).click();
  await expect(page.getByRole('button', { name: /east Computer favorite/ })).toBeVisible();
  drift = true; await page.getByRole('button', { name: 'Next', exact: true }).click();
  await expect(page.getByRole('alert')).toContainText('Directory snapshot changed');
  await expect(page.getByRole('button', { name: /east Computer favorite/ })).toHaveCount(0);
  drift = false; await page.getByRole('button', { name: 'Refresh favorites', exact: true }).click();
  await expect(page.getByRole('button', { name: /east Computer favorite/ })).toBeVisible();
});

test('environment switch discards a late favorite detail', async ({ page }, info) => {
  const state: State = { saved: new Set(['east-User', 'west-Group']) }; await mock(page, state); await page.goto('/#/favorites');
  let release: (() => void) | undefined;
  await page.route('**/directory/objects/east-User', async route => {
    await new Promise<void>(resolve => { release = resolve; });
    await route.fulfill({ contentType: 'application/json', body: JSON.stringify({ item: object('east', 'User'), asOf }) }).catch(() => {});
  });
  await page.getByRole('button', { name: /east User favorite/ }).click(); await expect.poll(() => Boolean(release)).toBe(true);
  if (info.project.name.includes('mobile')) await page.getByRole('button', { name: 'Open menu' }).click();
  await page.locator('.environment-picker select').selectOption('west'); release?.();
  await expect(page.getByRole('button', { name: /west Group favorite/ })).toBeVisible();
  await expect(page.getByText('east User favorite')).toHaveCount(0);
});

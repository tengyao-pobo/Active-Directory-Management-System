import { test, expect, type Page } from '@playwright/test';

interface State { status?: string; expired?: boolean; failDetail?: boolean; drift?: boolean; searches: string[] }
const asOf = '2026-09-11T13:00:00Z';
function object(env: string, kind: string, suffix = 'Alpha') {
  return { id: `${env}-${kind}-${suffix}`, kind, name: `${env} ${kind} ${suffix}`, distinguishedName: `CN=${suffix},OU=People,DC=${env},DC=test`,
    samAccountName: `${suffix.toLowerCase()}`, department: 'Operations', objectSid: 'S-1-5-21-100-200-300-1001', usnChanged: 42,
    protectionKnown: false, isProtected: false, parentOuId: 'synthetic-ou' };
}
async function mock(page: Page, state: State) {
  await page.addInitScript(() => localStorage.setItem('itmc.locale', 'en-US'));
  await page.route('**/api/v1/**', async route => {
    const u = new URL(route.request().url()); const path = u.pathname;
    const reply = (body: unknown, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
    if (path.endsWith('/session/me')) return reply({ id: 'scoped-operator', displayName: 'Scoped operator' });
    if (path.endsWith('/session/preferences')) return reply({ locale: 'en-US' });
    if (path === '/api/v1/environments') return reply({ items: ['east', 'west'].map(id => ({ id, name: `${id} environment`, canonicalDns: `${id}.test`, defaultLocale: 'en-US', version: 1 })) });
    if (path.endsWith('/access')) return reply({ permissions: [] }); // An OU-scoped reader has no All-resource capability.
    const m = path.match(/\/environments\/(east|west)\/directory\/(status|objects)(?:\/(.+))?$/);
    if (!m) return reply({ title: 'UnexpectedMockRoute' }, 404);
    if (state.expired) return reply({ title: 'SessionInvalid' }, 401);
    const [, env, resource, id] = m;
    if (resource === 'status') return reply({ status: state.status ?? 'Ready', stale: Boolean(state.status && state.status !== 'Ready'), completedAt: asOf, mutationAvailable: false });
    if (id) {
      if (state.failDetail) return reply({ title: 'NotFound' }, 404);
      const [, kind, suffix] = id.split('-'); return reply({ item: object(env, kind, suffix), asOf });
    }
    const kind = u.searchParams.get('kind') ?? 'User'; const search = u.searchParams.get('search') ?? '';
    state.searches.push(search);
    if (u.searchParams.has('cursor') && state.drift) { state.drift = false; return reply({ title: 'DirectorySnapshotChanged' }, 409); }
    const suffix = u.searchParams.has('cursor') ? 'Beta' : 'Alpha';
    return reply({ items: [object(env, kind, suffix)], nextCursor: suffix === 'Alpha' ? 'synthetic+cursor/=' : null, generation: 'synthetic-generation', asOf });
  });
}
async function open(page: Page, state: State, hash = 'users') { await mock(page, state); await page.goto(`/#/${hash}`); }

for (const [hash, kind, heading] of [['users', 'User', 'Users'], ['groups', 'Group', 'Groups'], ['computers', 'Computer', 'Computers'], ['ou', 'OrganizationalUnit', 'Organizational units']]) {
  test(`${kind} list and authorized detail support a scoped operator`, async ({ page }, info) => {
    await open(page, { searches: [] }, hash);
    await expect(page.getByRole('heading', { name: heading, exact: true })).toBeVisible();
    const link = page.getByRole('button', { name: new RegExp(`east ${kind} Alpha`) });
    await expect(link).toBeVisible(); await link.click();
    await expect(page.getByRole('heading', { name: 'Object details', exact: true })).toBeVisible();
    await expect(page.locator('.directory-detail')).toContainText('S-1-5-21-100-200-300-1001');
    await expect(page.locator('.directory-detail')).toContainText('Unknown');
    if (kind === 'User') await page.screenshot({ path: `test-results/screenshots/${info.project.name}-directory.png`, fullPage: true });
  });
}

test('search stays literal, pagination clears detail and generation drift restarts', async ({ page }) => {
  const state: State = { searches: [] }; await open(page, state);
  await page.getByRole('button', { name: /east User Alpha/ }).click();
  await page.getByLabel('Search directory', { exact: true }).fill('a*)(|(name=*)) + %');
  await page.getByRole('button', { name: 'Search', exact: true }).click();
  await expect.poll(() => state.searches.at(-1)).toBe('a*)(|(name=*)) + %');
  await expect(page.getByRole('heading', { name: 'Object details', exact: true })).toHaveCount(0);
  await page.getByRole('button', { name: 'Next', exact: true }).click();
  await expect(page.getByRole('button', { name: /east User Beta/ })).toBeVisible();
  await page.getByRole('button', { name: 'Previous', exact: true }).click();
  await expect(page.getByRole('button', { name: /east User Alpha/ })).toBeVisible();
  state.drift = true;
  await page.getByRole('button', { name: 'Next', exact: true }).click();
  await expect(page.getByText('The directory snapshot changed. Results restarted from the first page.')).toBeVisible();
  await expect(page.getByRole('button', { name: /east User Alpha/ })).toBeVisible();
});

for (const [status, title] of [['Unconfigured', 'Directory connector is not ready'], ['Failed', 'Directory sync failed']]) {
  test(`${status} is distinguished from an empty directory`, async ({ page }) => {
    await open(page, { status, searches: [] });
    await expect(page.getByRole('heading', { name: title })).toBeVisible();
    await expect(page.getByText('No authorized objects found')).toHaveCount(0);
  });
}

test('detail denial clears prior content and a protected 401 clears the console', async ({ page }) => {
  const state: State = { searches: [] }; await open(page, state);
  await page.getByRole('button', { name: /east User Alpha/ }).click();
  await expect(page.locator('.directory-detail')).toContainText('S-1-5-21');
  state.failDetail = true;
  await page.getByRole('button', { name: /east User Alpha/ }).click();
  await expect(page.getByRole('heading', { name: 'Directory not found', exact: true })).toBeVisible();
  await expect(page.locator('.directory-detail')).not.toContainText('S-1-5-21');
  state.expired = true;
  await page.getByRole('button', { name: 'Next', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Sign in to IT Management' })).toBeVisible();
  await expect(page.getByText('east User Alpha')).toHaveCount(0);
});

test('switching environments clears an in-flight detail response', async ({ page }, info) => {
  await open(page, { searches: [] });
  let release: (() => void) | undefined;
  await page.route('**/directory/objects/east-User-Alpha', async route => {
    await new Promise<void>(resolve => { release = resolve; });
    await route.fulfill({ contentType: 'application/json', body: JSON.stringify({ item: object('east', 'User'), asOf }) }).catch(() => {});
  });
  await page.getByRole('button', { name: /east User Alpha/ }).click();
  await expect.poll(() => Boolean(release)).toBe(true);
  if (info.project.name.includes('mobile')) await page.getByRole('button', { name: 'Open menu' }).click();
  await page.locator('.environment-picker select').selectOption('west');
  if (info.project.name.includes('mobile')) await page.getByRole('button', { name: 'Close menu', exact: true }).first().click();
  release?.();
  await expect(page.getByRole('button', { name: /west User Alpha/ })).toBeVisible();
  await expect(page.getByText('east User Alpha')).toHaveCount(0);
  await expect(page.getByRole('heading', { name: 'Object details', exact: true })).toHaveCount(0);
});

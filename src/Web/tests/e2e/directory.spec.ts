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
    if (path.includes('/favorites/')) return reply({ saved: false });
    if (path.match(/\/devices\/.+\/user$/)) return reply({ user: null, version: 0, updatedAt: null, canEdit: false });
    if (path.match(/\/users\/.+\/devices$/)) return reply({ items: [], nextCursor: null });
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

test('global search waits for submission, searches every kind and clears results', async ({ page }, info) => {
  const state: State = { searches: [] }; await open(page, state, 'search');
  await expect(page.getByRole('heading', { name: 'Directory search', exact: true })).toBeVisible();
  expect(state.searches).toEqual([]);
  await expect(page.getByRole('button', { name: 'Search', exact: true })).toBeDisabled();
  const literal = 'alpha + % &';
  await page.getByLabel('Search all directory types').fill(literal);
  await page.getByRole('button', { name: 'Search', exact: true }).click();
  await expect.poll(() => state.searches.length).toBe(4);
  expect(state.searches.every(value => value === literal)).toBe(true);
  for (const kind of ['User', 'Group', 'Computer', 'OrganizationalUnit']) await expect(page.getByRole('button', { name: new RegExp(`east ${kind} Alpha`) })).toBeVisible();
  await page.getByRole('button', { name: /east User Alpha/ }).click();
  await expect(page.locator('.directory-detail')).toContainText('S-1-5-21');
  await page.evaluate(() => { (document.activeElement as HTMLElement)?.blur(); window.scrollTo(0, 0); });
  await page.screenshot({ path: `test-results/screenshots/${info.project.name}-global-search.png`, fullPage: true });
  await page.locator('.global-directory-search > form').getByRole('button', { name: 'Clear search' }).click();
  await expect(page.locator('.directory-view')).toHaveCount(0);
});

test('global query replacement resets all details and cursors; environment switch removes query', async ({ page }, info) => {
  await open(page, { searches: [] }, 'search');
  await page.getByLabel('Search all directory types').fill('first');
  await page.locator('.global-directory-search > form').getByRole('button', { name: 'Search', exact: true }).click();
  const users = page.getByRole('region', { name: 'Users', exact: true });
  await users.getByRole('button', { name: 'Next', exact: true }).click();
  await users.getByRole('button', { name: /east User Beta/ }).click();
  await expect(users.locator('.directory-detail')).toContainText('Beta');
  await page.getByLabel('Search all directory types').fill('second');
  await page.locator('.global-directory-search > form').getByRole('button', { name: 'Search', exact: true }).click();
  await expect(users.getByRole('button', { name: /east User Alpha/ })).toBeVisible();
  await expect(page.locator('.directory-detail')).toHaveCount(0);
  if (info.project.name.includes('mobile')) await page.getByRole('button', { name: 'Open menu' }).click();
  await page.locator('.environment-picker select').selectOption('west');
  await expect(page.getByLabel('Search all directory types')).toHaveValue('');
  await expect(page.locator('.directory-view')).toHaveCount(0);
});

test('refresh recovers an unconfigured directory without reloading the app', async ({ page }) => {
  const state: State = { status: 'Unconfigured', searches: [] }; await open(page, state);
  await expect(page.getByRole('heading', { name: 'Directory connector is not ready' })).toBeVisible();
  state.status = 'Ready';
  await page.getByRole('button', { name: 'Refresh directory' }).click();
  await expect(page.getByRole('button', { name: /east User Alpha/ })).toBeVisible();
});

test('one unavailable type does not hide other search results or report ready', async ({ page }) => {
  await open(page, { searches: [] }, 'search');
  await page.route('**/directory/objects?**', route => {
    if (new URL(route.request().url()).searchParams.get('kind') !== 'Group') return route.fallback();
    return route.fulfill({ status: 503, contentType: 'application/json', body: JSON.stringify({ title: 'DirectoryUnavailable' }) });
  });
  await page.getByLabel('Search all directory types').fill('alpha');
  await page.getByRole('button', { name: 'Search', exact: true }).click();
  await expect(page.getByRole('button', { name: /east User Alpha/ })).toBeVisible();
  const groups = page.getByRole('region', { name: 'Groups', exact: true });
  await expect(groups.getByRole('alert')).toBeVisible();
  await expect(groups.locator('.directory-source')).not.toContainText('Snapshot ready');
});

test('a late old global search response cannot replace a new query', async ({ page }) => {
  await open(page, { searches: [] }, 'search');
  let release: (() => void) | undefined;
  await page.route('**/directory/objects?**', async route => {
    const u = new URL(route.request().url());
    if (u.searchParams.get('search') !== 'old' || u.searchParams.get('kind') !== 'User') return route.fallback();
    await new Promise<void>(resolve => { release = resolve; });
    await route.fulfill({ contentType: 'application/json', body: JSON.stringify({ items: [object('east', 'User', 'Obsolete')], nextCursor: null, generation: 'old', asOf }) }).catch(() => {});
  });
  await page.getByLabel('Search all directory types').fill('old');
  await page.getByRole('button', { name: 'Search', exact: true }).click();
  await expect.poll(() => Boolean(release)).toBe(true);
  await page.getByLabel('Search all directory types').fill('new');
  await page.locator('.global-directory-search > form').getByRole('button', { name: 'Search', exact: true }).click();
  release?.();
  await expect(page.getByRole('button', { name: /east User Alpha/ })).toBeVisible();
  await expect(page.getByText('east User Obsolete')).toHaveCount(0);
});

test('computer asset saves with CSRF and version, then exposes conflict without overwriting', async ({ page }) => {
  await open(page, { searches: [] }, 'computers');
  let version = 0; let notes = ''; let lifecycle = 'Unknown'; let conflict = false;
  await page.route('**/session/csrf', route => route.fulfill({ contentType: 'application/json', body: JSON.stringify({ token: 'test-csrf' }) }));
  await page.route('**/devices/**/asset', async route => {
    if (route.request().method() === 'PUT') {
      expect(route.request().headers()['x-csrf-token']).toBe('test-csrf');
      expect(route.request().headers()['if-match']).toBe(`"${version}"`);
      if (conflict) return route.fulfill({ status: 412 });
      notes = route.request().postDataJSON().notes; lifecycle = route.request().postDataJSON().lifecycle; version++;
    }
    return route.fulfill({ contentType: 'application/json', body: JSON.stringify({ item: version ? { lifecycle, notes, version, updatedAt: '2026-09-11T14:00:00Z' } : null, canEdit: true }) });
  });
  await page.getByRole('button', { name: /east Computer Alpha/ }).click();
  await page.getByRole('tab', { name: 'Asset', exact: true }).click();
  await page.getByLabel('IT notes', { exact: true }).fill('maintenance <script>literal</script>');
  await expect(page.getByRole('option', { name: 'Disposed', exact: true })).toHaveCount(1);
  await expect(page.getByRole('option', { name: 'Lost', exact: true })).toHaveCount(1);
  await page.getByLabel('Lifecycle', { exact: true }).selectOption('ReplacementPlanned');
  await page.getByRole('button', { name: 'Save asset' }).click();
  await expect(page.getByText('Saved.', { exact: true })).toBeVisible();
  await expect(page.getByText('Version 1')).toBeVisible();
  await expect(page.getByLabel('Lifecycle', { exact: true })).toHaveValue('ReplacementPlanned');
  conflict = true;
  await page.getByLabel('IT notes', { exact: true }).fill('unsaved draft');
  await page.getByRole('button', { name: 'Save asset' }).click();
  await expect(page.getByRole('alert')).toContainText('Someone changed this record');
  await page.getByRole('button', { name: 'Reload and discard edits' }).click();
  await expect(page.getByLabel('IT notes', { exact: true })).toHaveValue('maintenance <script>literal</script>');
});

test('manual user assignment saves explicit target and reverse view shows computer', async ({ page }) => {
  await open(page, { searches: [] }, 'computers');
  let assigned = false; let version = 0;
  await page.route('**/session/csrf', route => route.fulfill({ contentType: 'application/json', body: JSON.stringify({ token: 'test-csrf' }) }));
  await page.route('**/devices/**/user', async route => {
    if (route.request().method() === 'PUT') { expect(route.request().headers()['x-csrf-token']).toBe('test-csrf'); expect(route.request().headers()['if-match']).toBe(`"${version}"`); assigned = route.request().postDataJSON().userId !== null; version++; return route.fulfill({ status: 204 }); }
    return route.fulfill({ contentType: 'application/json', body: JSON.stringify({ user: assigned ? { id: 'east-User-Alpha', name: 'east User Alpha' } : null, version, canEdit: true, updatedAt: version ? '2026-09-11T14:00:00Z' : null }) });
  });
  await page.route('**/users/**/devices', route => route.fulfill({ contentType: 'application/json', body: JSON.stringify({ items: assigned ? [{ id: 'east-Computer-Alpha', name: 'east Computer Alpha', updatedAt: '2026-09-11T14:00:00Z' }] : [], nextCursor: null }) }));
  await page.getByRole('button', { name: /east Computer Alpha/ }).click();
  await page.getByRole('tab', { name: 'User', exact: true }).click();
  const panel = page.getByRole('region', { name: 'Person–computer association', exact: true });
  await panel.getByLabel('Find a user', { exact: true }).fill('Alpha');
  await panel.getByRole('button', { name: 'Search', exact: true }).click();
  await panel.getByRole('button', { name: 'east User Alpha (alpha)', exact: true }).click();
  await panel.getByRole('button', { name: 'Assign selected user' }).click();
  await expect(panel).toContainText('Assigned user: east User Alpha');
  await page.goto('/#/users'); await page.getByRole('button', { name: /east User Alpha/ }).click();
  await expect(page.getByRole('region', { name: 'Person–computer association', exact: true })).toContainText('east Computer Alpha');
  await page.goto('/#/computers'); await page.getByRole('button', { name: /east Computer Alpha/ }).click();
  await page.getByRole('tab', { name: 'User', exact: true }).click();
  await page.getByRole('button', { name: 'Clear current assignment' }).click();
  await expect(panel).toContainText('Unassigned');
  expect(version).toBe(2);
});

test('device deep link lazy loads tabs and supports keyboard navigation', async ({ page }, info) => {
  const requests: string[] = []; page.on('request', r => { if (r.url().includes('/devices/')) requests.push(r.url()); });
  await open(page, { searches: [] }, 'device?environment=east&id=east-Computer-Alpha');
  await expect(page.getByRole('heading', { name: 'east Computer Alpha', exact: true })).toBeVisible();
  expect(requests).toEqual([]);
  await page.route('**/devices/**/audit', route => route.fulfill({ contentType: 'application/json', body: JSON.stringify({ items: [{ id: 'event', action: 'Device.AssetUpdated', result: 'Success', occurredAt: '2026-09-11T14:00:00Z' }], nextCursor: null }) }));
  await page.getByRole('tab', { name: 'Audit', exact: true }).click();
  await expect(page.getByRole('tabpanel')).toContainText('Device.AssetUpdated');
  expect(requests.length).toBeGreaterThan(0);
  expect(requests.every(path => path.endsWith('/audit'))).toBe(true); // StrictMode may start and cancel a duplicate read.
  await page.getByRole('tab', { name: 'Audit', exact: true }).press('ArrowRight');
  await expect(page.getByRole('tab', { name: 'Inventory' })).toBeFocused();
  await expect(page.getByRole('tabpanel')).toContainText('Inventory source unavailable');
  await page.getByRole('tab', { name: 'Inventory' }).press('Home');
  await expect(page.getByRole('tab', { name: 'AD', exact: true })).toBeFocused();
  await page.screenshot({ path: `test-results/screenshots/${info.project.name}-device-details.png`, fullPage: true });
});

test('mismatched deep link does not fetch a device and late audit response is discarded', async ({ page }) => {
  const requests: string[] = []; page.on('request', r => { if (/\/directory\/objects\/|\/devices\//.test(r.url())) requests.push(r.url()); });
  await open(page, { searches: [] }, 'device?environment=west&id=east-Computer-Alpha');
  await expect(page.getByRole('alert')).toContainText('Select the environment'); expect(requests).toEqual([]);
  await page.goto('/#/device?environment=east&id=east-Computer-Alpha');
  await expect(page.getByRole('tab', { name: 'AD', exact: true })).toBeVisible();
  let release: (() => void) | undefined;
  await page.route('**/devices/**/audit', async route => { await new Promise<void>(resolve => { release = resolve; }); await route.fulfill({ contentType: 'application/json', body: JSON.stringify({ items: [{ id: 'old', action: 'old-audit-canary', result: 'Success', occurredAt: '2026-09-11T14:00:00Z' }], nextCursor: null }) }).catch(() => {}); });
  await page.getByRole('tab', { name: 'Audit', exact: true }).click(); await expect.poll(() => Boolean(release)).toBe(true);
  await page.goto('/#/device?environment=west&id=other'); release?.();
  await expect(page.getByRole('alert')).toContainText('Select the environment'); await expect(page.getByText('old-audit-canary')).toHaveCount(0);
});

test('department proposal uses CSRF and never enables approval', async ({ page }, info) => {
  await mock(page, { searches: [] });
  const writes: string[] = [];
  page.on('request', request => { if (request.method() === 'POST') writes.push(new URL(request.url()).pathname); });
  await page.route('**/session/csrf', route => route.fulfill({ contentType: 'application/json', body: JSON.stringify({ token: 'proposal-csrf' }) }));
  await page.route('**/directory/users/*/proposal', async route => {
    expect(route.request().headers()['x-csrf-token']).toBe('proposal-csrf');
    expect(route.request().postDataJSON()).toEqual({ kind: 'SetUserDepartment', department: 'Finance' });
    return route.fulfill({ contentType: 'application/json', body: JSON.stringify({ environmentId: 'east', target: object('east', 'User'), kind: 'SetUserDepartment', before: 'Operations', after: 'Finance', asOf: new Date().toISOString(), snapshotValidUntil: new Date(Date.now()+60000).toISOString(), approvalAvailable: false, executionAvailable: false, blockers: ['ProtectionClassificationUnavailable','ApprovalWorkflowUnavailable','DirectoryWritesNotConfigured'] }) });
  });
  await page.goto('/#/users'); await page.getByRole('button', { name: /east User Alpha/ }).click();
  await page.getByLabel('Proposed department', { exact: true }).fill('Finance');
  await page.getByRole('button', { name: 'Preview proposal', exact: true }).click();
  const review=page.getByRole('region', {name:'Review proposal'});
  await expect(review).toContainText('Operations'); await expect(review).toContainText('Finance'); await expect(review).toContainText('CN=Alpha');
  await expect(page.getByRole('button',{name:'Approval unavailable',exact:true})).toBeDisabled();
  await page.screenshot({path:`test-results/screenshots/${info.project.name}-proposal.png`,fullPage:true});
  await page.getByLabel('Proposed department', {exact:true}).fill('Legal'); await expect(review).toHaveCount(0);
  expect(writes).toEqual(['/api/v1/environments/east/directory/users/east-User-Alpha/proposal']);
});

test('proposal denial never leaves a comparison', async ({page}) => {
  await mock(page,{searches:[]});
  await page.route('**/session/csrf',route=>route.fulfill({contentType:'application/json',body:JSON.stringify({token:'csrf'})}));
  await page.route('**/directory/users/*/proposal',route=>route.fulfill({status:404,contentType:'application/json',body:'{}'}));
  await page.goto('/#/users'); await page.getByRole('button',{name:/east User Alpha/}).click();
  await page.getByLabel('Proposed department',{exact:true}).fill('Finance'); await page.getByRole('button',{name:'Preview proposal',exact:true}).click();
  await expect(page.getByRole('alert')).toContainText('Preview unavailable');
  await expect(page.getByRole('region',{name:'Review proposal'})).toHaveCount(0);
});

test('expired and late proposals are discarded', async ({page}) => {
  await mock(page,{searches:[]});
  await page.route('**/session/csrf',route=>route.fulfill({contentType:'application/json',body:JSON.stringify({token:'csrf'})}));
  let release: (()=>void)|undefined;
  let late=false;
  await page.route('**/directory/users/*/proposal',async route=>{
    if(late) await new Promise<void>(resolve=>{release=resolve;});
    await route.fulfill({contentType:'application/json',body:JSON.stringify({environmentId:'east',target:object('east','User'),kind:'SetUserDepartment',before:'Operations',after:'late-secret-canary',asOf:new Date().toISOString(),snapshotValidUntil:new Date(Date.now()+(late?60000:-1000)).toISOString(),blockers:[]})});
  });
  await page.goto('/#/users'); await page.getByRole('button',{name:/east User Alpha/}).click();
  await page.getByLabel('Proposed department',{exact:true}).fill('Finance'); await page.getByRole('button',{name:'Preview proposal',exact:true}).click();
  await expect(page.getByText('The snapshot expired. Generate a new preview.')).toBeVisible();
  late=true; await page.getByRole('button',{name:'Preview proposal',exact:true}).click();
  await expect.poll(()=>Boolean(release)).toBe(true);
  if (await page.getByRole('button',{name:'Open menu',exact:true}).isVisible()) await page.getByRole('button',{name:'Open menu',exact:true}).click();
  await page.getByRole('button',{name:'Groups',exact:true}).click(); release!();
  await expect(page.getByRole('heading',{name:'Groups',exact:true})).toBeVisible();
  await expect(page.getByText('late-secret-canary')).toHaveCount(0);
});

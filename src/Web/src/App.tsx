import DeviceTagPanel from './DeviceTagPanel';
import { FormEvent, useEffect, useRef, useState } from 'react';
import {
  ApiError,
  enrollPasskey,
  getAccess,
  getAudit,
  getEnvironments,
  getPreference,
  getRbac,
  getSession,
  loginEmergency,
  loginWindows,
  logout,
  savePreference,
  type AuditPage,
  type ManagedEnvironment,
  type Principal,
  type Rbac,
} from './api';
import { useI18n } from './i18n';
import './styles.css';
import DirectoryView from './DirectoryView';
import DirectorySearch from './DirectorySearch';
import Dashboard from './Dashboard';
import DeviceDetails from './DeviceDetails';
import FavoritesView from './FavoritesView';
import { getDirectoryStatus, type DirectoryKind, type DirectoryStatus } from './api';

type View = 'overview' | 'environment' | 'access' | 'audit' | 'settings' | 'users' | 'groups' | 'computers' | 'ou' | 'search' | 'device' | 'favorites' | 'tags';
type AsyncState = 'idle' | 'loading' | 'ready' | 'empty' | 'error';

type AccessData = { permissions: string[] };
type RbacData = Rbac;
type AuditData = AuditPage;

const views: View[] = ['overview', 'environment', 'access', 'audit', 'settings', 'users', 'groups', 'computers', 'ou', 'search', 'device', 'favorites', 'tags'];
const directoryKinds: Partial<Record<View, DirectoryKind>> = { users: 'User', groups: 'Group', computers: 'Computer', ou: 'OrganizationalUnit' };

function routeFromHash(): View {
  const route = window.location.hash.replace(/^#\/?/, '').split('?')[0];
  return views.includes(route as View) ? (route as View) : 'overview';
}

function errorKey(error: unknown): string {
  if (error instanceof ApiError) {
    const known: Record<string, string> = {
      AuthenticationFailed: 'error.invalidCredentials',
      AuthenticatorInvalid: 'error.passkey',
      PasskeyCancelled: 'error.passkey',
      PasskeyUnavailable: 'error.passkey',
      PasskeyNotEnrolled: 'error.passkeyNotEnrolled',
      CeremonyInvalid: 'error.passkey',
      WindowsAuthenticationUnavailable: 'error.windowsUnavailable',
      KerberosRequired: 'error.kerberosRequired',
      NotProvisioned: 'error.notProvisioned',
      EmergencyLoginUnavailable: 'error.emergencyUnavailable',
      NetworkUnavailable: 'error.network',
    };
    if (error.code && known[error.code]) return known[error.code];
    if (error.status === 401) return 'error.unauthorized';
    if (error.status === 403) return 'error.forbidden';
  }
  return 'error.generic';
}

function App() {
  const { t, locale, setLocale } = useI18n();
  const [principal, setPrincipal] = useState<Principal | null>(null);
  const [authState, setAuthState] = useState<AsyncState>('loading');
  const [authError, setAuthError] = useState<string>('');
  const [routeHash, setRouteHash] = useState(window.location.hash);
  const [view, setView] = useState<View>(routeFromHash);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [pageSearch, setPageSearch] = useState('');
  const [environments, setEnvironments] = useState<ManagedEnvironment[]>([]);
  const [environmentId, setEnvironmentId] = useState('');
  const [loadedEnvironmentId, setLoadedEnvironmentId] = useState('');
  const [envState, setEnvState] = useState<AsyncState>('idle');
  const [dataState, setDataState] = useState<AsyncState>('idle');
  const [dataError, setDataError] = useState('');
  const [access, setAccess] = useState<AccessData | null>(null);
  const [rbac, setRbac] = useState<RbacData | null>(null);
  const [audit, setAudit] = useState<AuditData | null>(null);
  const [auditCursor, setAuditCursor] = useState<string | undefined>();
  const [auditHistory, setAuditHistory] = useState<(string | undefined)[]>([]);
  const requestGeneration = useRef(0);

  const isDirectory = Boolean(directoryKinds[view]) || view === 'search' || view === 'device' || view === 'favorites' || view === 'tags';
  const targetParams = new URLSearchParams(routeHash.split('?')[1] ?? '');
  const environment = environments.find((item) => item.id === environmentId) ?? null;

  useEffect(() => {
    const onHash = () => {
      setRouteHash(window.location.hash);
      setView(routeFromHash());
      setSidebarOpen(false);
      setPageSearch('');
    };
    window.addEventListener('hashchange', onHash);
    return () => window.removeEventListener('hashchange', onHash);
  }, []);

  useEffect(() => {
    let active = true;
    void (async () => {
      try {
        const current = await getSession(undefined, true);
        if (!active) return;
        setPrincipal(current);
        setAuthState(current ? 'ready' : 'empty');
        if (current) {
          try {
            const preference = await getPreference();
            if (active && (preference?.locale === 'zh-TW' || preference?.locale === 'en-US')) {
              setLocale(preference.locale);
            }
          } catch {
            // A preference failure must not block an authenticated session.
          }
        }
      } catch (error) {
        if (!active) return;
        if (error instanceof ApiError && error.status === 401) {
          setAuthState('empty');
        } else {
          setAuthError(errorKey(error));
          setAuthState('error');
        }
      }
    })();
    return () => { active = false; };
  }, [setLocale]);

  useEffect(() => {
    const expire = () => {
      requestGeneration.current += 1;
      setPrincipal(null);
      setEnvironments([]);
      setEnvironmentId('');
      setLoadedEnvironmentId('');
      setAccess(null);
      setRbac(null);
      setAudit(null);
      setAuthError('error.sessionExpired');
      setAuthState('empty');
    };
    window.addEventListener('itmc:session-expired', expire);
    return () => window.removeEventListener('itmc:session-expired', expire);
  }, []);

  useEffect(() => {
    if (!principal) return;
    const generation = ++requestGeneration.current;
    setEnvState('loading');
    const controller = new AbortController();
    void getEnvironments(controller.signal)
      .then((items) => {
        if (generation !== requestGeneration.current) return;
        setEnvironments(items);
        setEnvironmentId((current) => items.some((item) => item.id === current) ? current : (items[0]?.id ?? ''));
        setEnvState(items.length ? 'ready' : 'empty');
      })
      .catch((error) => {
        if (generation !== requestGeneration.current) return;
        setDataError(errorKey(error));
        setEnvState('error');
      });
    return () => controller.abort();
  }, [principal]);

  useEffect(() => {
    setAuditCursor(undefined);
    setAuditHistory([]);
  }, [environmentId]);

  useEffect(() => {
    if (!principal || !environmentId) {
      setAccess(null);
      setRbac(null);
      setAudit(null);
      setLoadedEnvironmentId('');
      setDataState('idle');
      return;
    }
    const controller = new AbortController();
    const generation = ++requestGeneration.current;
    setDataState('loading');
    setDataError('');
    void getAccess(environmentId, controller.signal).then(async (nextAccess) => {
      const [nextRbac, nextAudit] = await Promise.all([
        nextAccess.permissions.includes('RBAC.Manage') ? getRbac(environmentId, controller.signal) : Promise.resolve(null),
        nextAccess.permissions.includes('Audit.View') ? getAudit(environmentId, auditCursor, controller.signal) : Promise.resolve(null),
      ]);
      if (controller.signal.aborted || generation !== requestGeneration.current) return;
      setAccess(nextAccess);
      setRbac(nextRbac);
      setAudit(nextAudit);
      setLoadedEnvironmentId(environmentId);
      setDataState('ready');
    }).catch((error) => {
      if (controller.signal.aborted || generation !== requestGeneration.current) return;
      setDataError(errorKey(error));
      setLoadedEnvironmentId('');
      setDataState('error');
    });
    return () => controller.abort();
  }, [principal, environmentId, auditCursor]);

  const navigate = (next: View) => {
    window.location.hash = `/${next}`;
  };

  const finishLogin = async (action: () => Promise<void>) => {
    setAuthState('loading');
    setAuthError('');
    try {
      await action();
      const next = await getSession();
      setPrincipal(next);
      setAuthState('ready');
      try {
        const preference = await getPreference();
        if (preference?.locale === 'zh-TW' || preference?.locale === 'en-US') setLocale(preference.locale);
      } catch {
        // Keep the local locale when server preferences are unavailable.
      }
    } catch (error) {
      setAuthError(errorKey(error));
      setAuthState('error');
    }
  };

  const doLogout = async () => {
    setAuthError('');
    try { await logout(); }
    catch (error) {
      if (!(error instanceof ApiError && error.status === 401)) setAuthError('error.logoutFailed');
      return;
    }
    {
      requestGeneration.current += 1;
      setPrincipal(null);
      setEnvironments([]);
      setEnvironmentId('');
      setLoadedEnvironmentId('');
      setAccess(null);
      setRbac(null);
      setAudit(null);
      setAuthState('empty');
    }
  };

  if (!principal) {
    return <LoginScreen state={authState} error={authError} onLogin={finishLogin} t={t} locale={locale} setLocale={setLocale} />;
  }

  const navMatches = (label: string) => t(`nav.${label}`).toLocaleLowerCase(locale).includes(pageSearch.trim().toLocaleLowerCase(locale));

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">{t('a11y.skip')}</a>
      <aside className={`sidebar ${sidebarOpen ? 'is-open' : ''}`} aria-label={t('a11y.primaryNav')}>
        <div className="brand-row">
          <span className="brand-mark" aria-hidden="true"><i /><i /><i /></span>
          <span><strong>ITMC</strong><small>{t('brand.subtitle')}</small></span>
          <button className="icon-button sidebar-close" onClick={() => setSidebarOpen(false)} aria-label={t('action.closeMenu')}>×</button>
        </div>
        <label className="environment-picker">
          <span>{t('environment.current')}</span>
          <select value={environmentId} onChange={(event) => {
            setAccess(null);
            setRbac(null);
            setAudit(null);
            setLoadedEnvironmentId('');
            setDataState('loading');
            setEnvironmentId(event.target.value);
          }} disabled={envState !== 'ready'}>
            {environments.length === 0 && <option value="">{envState === 'loading' ? t('state.loading') : t('state.unconfigured')}</option>}
            {environments.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}
          </select>
        </label>
        <nav>
          <NavGroup title={t('nav.group.workspace')}>
            {navMatches('overview') && <NavButton active={view === 'overview'} icon="⌂" label={t('nav.overview')} onClick={() => navigate('overview')} />}
            {navMatches('environment') && <NavButton active={view === 'environment'} icon="◇" label={t('nav.environment')} onClick={() => navigate('environment')} />}
          </NavGroup>
          <NavGroup title={t('nav.group.directory')}>
            {(['search', 'favorites', 'tags', 'computers', 'users', 'groups', 'ou'] as const).filter(navMatches).map(item => <NavButton key={item} active={view === item} icon="◇" label={t(`nav.${item}`)} onClick={() => navigate(item)} />)}
          </NavGroup>
          <NavGroup title={t('nav.group.system')}>
            {navMatches('access') && <NavButton active={view === 'access'} icon="⌑" label={t('nav.access')} onClick={() => navigate('access')} />}
            {navMatches('audit') && <NavButton active={view === 'audit'} icon="≡" label={t('nav.audit')} onClick={() => navigate('audit')} />}
            {navMatches('settings') && <NavButton active={view === 'settings'} icon="⚙" label={t('nav.settings')} onClick={() => navigate('settings')} />}
          </NavGroup>
        </nav>
        <div className="sidebar-status" role="status">
          <span className="status-dot" />
          <span><strong>{t('status.console')}</strong><small>{environment ? t('status.environmentSelected') : t('status.noEnvironment')}</small></span>
        </div>
      </aside>
      {sidebarOpen && <button className="sidebar-scrim" onClick={() => setSidebarOpen(false)} aria-label={t('action.closeMenu')} />}
      <section className="workspace">
        <header className="topbar">
          <button className="icon-button menu-button" onClick={() => setSidebarOpen(true)} aria-label={t('action.openMenu')}>☰</button>
          <div className="breadcrumb"><span>{t('brand.console')}</span><b>/</b><strong>{t(`nav.${view}`)}</strong></div>
          <label className="page-search">
            <span aria-hidden="true">⌕</span>
            <span className="sr-only">{t('search.label')}</span>
            <input value={pageSearch} onChange={(event) => setPageSearch(event.target.value)} placeholder={t('search.label')} />
            <kbd>/</kbd>
          </label>
          <div className="account">
            <span className="avatar" aria-hidden="true">{(principal.displayName || principal.id).slice(0, 1).toUpperCase()}</span>
            <span className="account-copy"><strong>{principal.displayName || principal.id}</strong><small>{t('account.signedIn')}</small></span>
            <button className="text-button" onClick={doLogout}>{t('action.signOut')}</button>
          </div>
        </header>
        <main id="main-content" tabIndex={-1}>
          {authError && <div className="inline-alert" role="alert">{t(authError)}</div>}
          {!isDirectory && <PageHeader view={view} environment={environment} t={t} />}
          {envState === 'loading' && <StatePanel kind="loading" title={t('state.loadingEnvironments')} t={t} />}
          {envState === 'error' && <StatePanel kind="error" title={t(dataError || 'error.generic')} t={t} />}
          {envState === 'empty' && <StatePanel kind="empty" title={t('environment.noneTitle')} body={t('environment.noneBody')} t={t} />}
          {envState === 'ready' && environment && view === 'device' && <DeviceDetails key={environment.id + ':' + routeHash} environmentId={environment.id} targetEnvironment={targetParams.get('environment') ?? ''} id={targetParams.get('id') ?? ''} />}
          {envState === 'ready' && environment && view === 'search' && <DirectorySearch key={environment.id} environmentId={environment.id} />}
          {envState === 'ready' && environment && view === 'tags' && <DeviceTagPanel key={environment.id} environmentId={environment.id} />}
          {envState === 'ready' && environment && view === 'favorites' && <FavoritesView key={environment.id} environmentId={environment.id} />}
          {envState === 'ready' && environment && directoryKinds[view] && <DirectoryView key={`${environment.id}:${view}`} environmentId={environment.id} kind={directoryKinds[view]!} />}
          {!isDirectory && envState === 'ready' && dataState === 'loading' && <StatePanel kind="loading" title={t('state.loadingData')} t={t} />}
          {!isDirectory && envState === 'ready' && dataState === 'error' && <StatePanel kind="error" title={t(dataError || 'error.generic')} t={t} />}
          {!isDirectory && envState === 'ready' && dataState === 'ready' && environment && loadedEnvironmentId === environment.id && (
            <PageContent view={view} environment={environment} access={access} rbac={rbac} audit={audit} locale={locale} setLocale={setLocale} t={t}
              onAuditNext={() => { if (audit?.nextCursor) { setDataState('loading'); setAuditHistory((items) => [...items, auditCursor]); setAuditCursor(audit.nextCursor); } }}
              onAuditPrevious={() => { setDataState('loading'); const previous = auditHistory[auditHistory.length - 1]; setAuditHistory((items) => items.slice(0, -1)); setAuditCursor(previous); }}
              hasAuditPrevious={auditHistory.length > 0} />
          )}
        </main>
      </section>
    </div>
  );
}

function LoginScreen({ state, error, onLogin, t, locale, setLocale }: {
  state: AsyncState; error: string; onLogin: (action: () => Promise<void>) => Promise<void>;
  t: ReturnType<typeof useI18n>['t']; locale: 'zh-TW' | 'en-US'; setLocale: (value: 'zh-TW' | 'en-US') => void;
}) {
  const [advanced, setAdvanced] = useState(false);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [token, setToken] = useState('');
  const [enrollState, setEnrollState] = useState<AsyncState>('idle');
  const [enrollError, setEnrollError] = useState('');
  const busy = state === 'loading';
  const submitEmergency = async (event: FormEvent) => {
    event.preventDefault();
    const user = username;
    const secret = password;
    setPassword('');
    try { await onLogin(() => loginEmergency(user, secret)); }
    finally { setPassword(''); }
  };
  const submitEnrollment = async (event: FormEvent) => {
    event.preventDefault();
    const registrationToken = token;
    setToken('');
    setEnrollState('loading');
    setEnrollError('');
    try { await enrollPasskey(registrationToken); setEnrollState('ready'); }
    catch (caught) { setEnrollError(errorKey(caught)); setEnrollState('error'); }
    finally { setToken(''); }
  };
  return (
    <main className="login-page">
      <div className="login-atmosphere" aria-hidden="true" />
      <header className="login-header">
        <div className="brand-row"><span className="brand-mark" aria-hidden="true"><i /><i /><i /></span><span><strong>ITMC</strong><small>{t('brand.subtitle')}</small></span></div>
        <LocaleToggle locale={locale} onChange={setLocale} t={t} compact />
      </header>
      <section className="login-card" aria-labelledby="login-title">
        <div className="eyebrow">{t('login.secureAccess')}</div>
        <h1 id="login-title">{t('login.title')}</h1>
        <p className="login-intro">{t('login.intro')}</p>
        {error && <div className="inline-alert" role="alert"><span>!</span>{t(error)}</div>}
        <button className="primary-button windows-button" disabled={busy} onClick={() => void onLogin(loginWindows)}>
          <span className="windows-mark" aria-hidden="true"><i /><i /><i /><i /></span>
          {busy ? t('state.signingIn') : t('login.windows')}
        </button>
        <div className="divider"><span>{t('login.orEmergency')}</span></div>
        <form onSubmit={submitEmergency}>
          <label>{t('login.username')}<input autoComplete="username" value={username} onChange={(event) => setUsername(event.target.value)} required /></label>
          <label>{t('login.password')}<input type="password" autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} required /></label>
          <button className="secondary-button" disabled={busy} type="submit">{t('login.emergency')}</button>
        </form>
        <div className="advisory"><strong>{t('login.advisoryTitle')}</strong><p>{t('login.advisoryBody')}</p></div>
        <button className="advanced-toggle" aria-expanded={advanced} onClick={() => setAdvanced((value) => !value)}>{advanced ? '−' : '+'} {t('login.advanced')}</button>
        {advanced && <form className="enrollment" onSubmit={submitEnrollment}>
          <label>{t('login.registrationToken')}<input type="password" autoComplete="off" value={token} onChange={(event) => setToken(event.target.value)} required /></label>
          <button className="secondary-button" disabled={busy} type="submit">{t('login.enroll')}</button>
          <small>{t('login.enrollHelp')}</small>
          {enrollState === 'loading' && <small className="form-status" role="status">{t('login.enrolling')}</small>}
          {enrollState === 'ready' && <small className="form-status success" role="status">{t('login.enrollSuccess')}</small>}
          {enrollState === 'error' && <small className="form-status error" role="alert">{t(enrollError || 'error.generic')}</small>}
        </form>}
      </section>
      <footer className="login-footer"><span className="status-dot" />{t('login.footer')}</footer>
    </main>
  );
}

function PageHeader({ view, environment, t }: { view: View; environment: ManagedEnvironment | null; t: ReturnType<typeof useI18n>['t'] }) {
  return <div className="page-heading"><div><div className="eyebrow">{t(`page.${view}.eyebrow`)}</div><h1>{t(`page.${view}.title`)}</h1><p>{t(`page.${view}.description`)}</p></div><div className="context-chip"><span className="status-dot" /><span>{t('environment.context')}<strong>{environment?.name ?? '—'}</strong></span></div></div>;
}

function PageContent({ view, environment, access, rbac, audit, locale, setLocale, t, onAuditNext, onAuditPrevious, hasAuditPrevious }: {
  view: View; environment: ManagedEnvironment; access: AccessData | null; rbac: RbacData | null; audit: AuditData | null;
  locale: 'zh-TW' | 'en-US'; setLocale: (value: 'zh-TW' | 'en-US') => void; t: ReturnType<typeof useI18n>['t'];
  onAuditNext: () => void; onAuditPrevious: () => void; hasAuditPrevious: boolean;
}) {
  if (view === 'overview') return <Overview environment={environment} access={access} rbac={rbac} audit={audit} t={t} />;
  if (view === 'environment') return <EnvironmentPage environment={environment} t={t} />;
  if ((view === 'access' && !access?.permissions.includes('RBAC.Manage')) || (view === 'audit' && !access?.permissions.includes('Audit.View')))
    return <StatePanel kind="error" title={t('error.forbidden')} t={t} />;
  if (view === 'access') return <AccessPage rbac={rbac} t={t} />;
  if (view === 'audit') return <AuditPage audit={audit} locale={locale} t={t} onNext={onAuditNext} onPrevious={onAuditPrevious} hasPrevious={hasAuditPrevious} />;
  return <SettingsPage locale={locale} setLocale={setLocale} t={t} />;
}

function Overview({ environment, access, rbac, audit, t }: { environment: ManagedEnvironment; access: AccessData | null; rbac: RbacData | null; audit: AuditData | null; t: ReturnType<typeof useI18n>['t'] }) {
  const cards = [
    [t('overview.environment'), environment.name, t('overview.environmentHint')],
    [t('overview.permissions'), access ? String(access.permissions.length) : '—', t('overview.permissionsHint')],
    [t('overview.roles'), rbac ? String(rbac.roles.length) : '—', t('overview.rolesHint')],
    [t('overview.auditEvents'), audit ? String(audit.items.length) : '—', t('overview.auditHint')],
  ];
  return <div className="content-grid">
    <Dashboard key={environment.id} environmentId={environment.id} />
    <section className="metric-grid" aria-label={t('overview.operationalStatus')}>{cards.map(([label, value, hint]) => <article className="metric-card" key={label}><span>{label}</span><strong>{value}</strong><small>{hint}</small></article>)}</section>
    <section className="panel integration-panel"><PanelTitle title={t('overview.readiness')} subtitle={t('overview.readinessSubtitle')} />
      <div className="readiness-list"><ReadinessRow label={t('overview.consoleApi')} status={t('status.available')} ready /><ConnectorReadiness key={environment.id} environmentId={environment.id} /><ReadinessRow label={t('overview.auditPipeline')} status={audit ? t('status.available') : t('status.unavailable')} ready={Boolean(audit)} /></div>
    </section>
    <section className="panel summary-panel"><PanelTitle title={t('overview.environmentSummary')} subtitle={t('overview.environmentSummarySubtitle')} />
      <DefinitionGrid rows={[[t('field.name'), environment.name], [t('field.dns'), environment.canonicalDns || '—'], [t('field.version'), String(environment.version || '—')], [t('field.defaultLocale'), environment.defaultLocale || '—']]} />
    </section>
  </div>;
}

function EnvironmentPage({ environment, t }: { environment: ManagedEnvironment; t: ReturnType<typeof useI18n>['t'] }) {
  return <section className="panel"><PanelTitle title={t('environment.details')} subtitle={t('environment.detailsSubtitle')} /><DefinitionGrid rows={[[t('field.id'), environment.id], [t('field.name'), environment.name], [t('field.dns'), environment.canonicalDns || '—'], [t('field.version'), String(environment.version || '—')], [t('field.defaultLocale'), environment.defaultLocale || '—']]} /><div className="notice neutral"><span>i</span><div><strong>{t('environment.readOnlyTitle')}</strong><p>{t('environment.readOnlyBody')}</p></div></div></section>;
}

function AccessPage({ rbac, t }: { rbac: RbacData | null; t: ReturnType<typeof useI18n>['t'] }) {
  if (!rbac || rbac.assignments.length === 0) return <StatePanel kind="empty" title={t('access.emptyTitle')} body={t('access.emptyBody')} t={t} />;
  const roleMap = new Map(rbac.roles.map((role) => [role.id, role]));
  const scopeMap = new Map(rbac.scopes.map((scope) => [scope.id, scope]));
  return <section className="panel table-panel"><PanelTitle title={t('access.assignments')} subtitle={t('access.readOnly')} badge={t('badge.readOnly')} /><div className="table-scroll"><table><thead><tr><th>{t('access.principal')}</th><th>{t('access.role')}</th><th>{t('access.scope')}</th><th>{t('access.inheritance')}</th><th>{t('access.permissions')}</th></tr></thead><tbody>{rbac.assignments.map((assignment) => { const role = roleMap.get(assignment.roleId); const scope = scopeMap.get(assignment.scopeId); const permissions = rbac.permissions.filter((item) => item.roleId === assignment.roleId); return <tr key={assignment.id}><td><code>{assignment.principalId}</code></td><td><strong>{role?.name ?? assignment.roleId}</strong>{role?.builtInKind && <small>{role.builtInKind}</small>}</td><td><span className="scope-kind">{scope?.kind ?? '—'}</span>{scope?.value ?? '—'}</td><td>{scope?.includeDescendants ? t('access.included') : t('access.exact')}</td><td><span className="count-badge">{permissions.length}</span></td></tr>; })}</tbody></table></div></section>;
}

function AuditPage({ audit, locale, t, onNext, onPrevious, hasPrevious }: { audit: AuditData | null; locale: string; t: ReturnType<typeof useI18n>['t']; onNext: () => void; onPrevious: () => void; hasPrevious: boolean }) {
  if (!audit || audit.items.length === 0) return <StatePanel kind="empty" title={t('audit.emptyTitle')} body={t('audit.emptyBody')} t={t} />;
  return <section className="panel table-panel"><PanelTitle title={t('audit.events')} subtitle={t('audit.eventsSubtitle')} /><div className="table-scroll"><table><thead><tr><th>{t('audit.time')}</th><th>{t('audit.action')}</th><th>{t('audit.result')}</th><th>{t('audit.actor')}</th><th>{t('audit.target')}</th><th>{t('audit.correlation')}</th></tr></thead><tbody>{audit.items.map((item) => <tr key={item.id}><td className="nowrap">{formatDate(item.occurredAt, locale)}</td><td><strong>{item.action}</strong></td><td><span className={`result-pill ${item.result.toLowerCase()}`}>{item.result}</span></td><td><code>{item.actorId || '—'}</code></td><td><code>{item.targetId || '—'}</code></td><td><code>{item.correlationId}</code></td></tr>)}</tbody></table></div><div className="pagination"><button className="secondary-button" disabled={!hasPrevious} onClick={onPrevious}>{t('action.previous')}</button><span>{t('audit.pageStatus')}</span><button className="secondary-button" disabled={!audit.nextCursor} onClick={onNext}>{t('action.next')}</button></div></section>;
}

function SettingsPage({ locale, setLocale, t }: { locale: 'zh-TW' | 'en-US'; setLocale: (value: 'zh-TW' | 'en-US') => void; t: ReturnType<typeof useI18n>['t'] }) {
  const [saveState, setSaveState] = useState<AsyncState>('idle');
  const change = async (value: 'zh-TW' | 'en-US') => {
    setLocale(value);
    setSaveState('loading');
    try { await savePreference(value); setSaveState('ready'); }
    catch { setSaveState('error'); }
  };
  return <section className="panel settings-panel"><PanelTitle title={t('settings.language')} subtitle={t('settings.languageSubtitle')} /><fieldset disabled={saveState === 'loading'}><legend>{t('settings.displayLanguage')}</legend><LocaleToggle locale={locale} onChange={(value) => void change(value)} t={t} /></fieldset><div className={`save-status ${saveState}`} role="status">{saveState === 'loading' ? t('state.saving') : saveState === 'ready' ? t('state.saved') : saveState === 'error' ? t('error.preference') : t('settings.preferenceHint')}</div></section>;
}

function LocaleToggle({ locale, onChange, t, compact = false }: { locale: 'zh-TW' | 'en-US'; onChange: (value: 'zh-TW' | 'en-US') => void; t: ReturnType<typeof useI18n>['t']; compact?: boolean }) {
  return <div className={`locale-toggle ${compact ? 'compact' : ''}`} role="group" aria-label={t('settings.displayLanguage')}><button className={locale === 'zh-TW' ? 'active' : ''} aria-pressed={locale === 'zh-TW'} onClick={() => onChange('zh-TW')}>{t('locale.zhTW')}</button><button className={locale === 'en-US' ? 'active' : ''} aria-pressed={locale === 'en-US'} onClick={() => onChange('en-US')}>{t('locale.enUS')}</button></div>;
}

function StatePanel({ kind, title, body, t }: { kind: 'loading' | 'empty' | 'error'; title: string; body?: string; t: ReturnType<typeof useI18n>['t'] }) {
  return <section className={`state-panel ${kind}`} role={kind === 'error' ? 'alert' : 'status'}><span className="state-icon" aria-hidden="true">{kind === 'loading' ? <i className="spinner" /> : kind === 'error' ? '!' : '◇'}</span><h2>{title}</h2>{body && <p>{body}</p>}<small>{kind === 'error' ? t('error.safeDetail') : kind === 'loading' ? t('state.pleaseWait') : t('state.noRecords')}</small></section>;
}

function PanelTitle({ title, subtitle, badge }: { title: string; subtitle: string; badge?: string }) { return <div className="panel-title"><div><h2>{title}</h2><p>{subtitle}</p></div>{badge && <span className="badge">{badge}</span>}</div>; }
function DefinitionGrid({ rows }: { rows: [string, string][] }) { return <dl className="definition-grid">{rows.map(([term, value]) => <div key={term}><dt>{term}</dt><dd>{value}</dd></div>)}</dl>; }
function ReadinessRow({ label, status, ready = false }: { label: string; status: string; ready?: boolean }) { return <div><span className={`status-dot ${ready ? '' : 'muted'}`} /><strong>{label}</strong><span className={ready ? 'positive' : 'muted-text'}>{status}</span></div>; }
function ConnectorReadiness({ environmentId }: { environmentId: string }) {
  const { t } = useI18n();
  const [status, setStatus] = useState<DirectoryStatus | null>(null);
  useEffect(() => {
    const controller = new AbortController();
    void getDirectoryStatus(environmentId, controller.signal).then(value => { if (!controller.signal.aborted) setStatus(value); }).catch(() => {});
    return () => controller.abort();
  }, [environmentId]);
  const ready = status?.status === 'Ready' && !status.stale;
  const label = ready ? 'status.available' : status?.status === 'Unconfigured' ? 'state.unconfigured' : status?.status === 'Failed' ? 'directory.statusFailed' : 'status.unavailable';
  return <ReadinessRow label={t('overview.directoryConnector')} status={t(label)} ready={ready} />;
}
function NavGroup({ title, children }: { title: string; children: React.ReactNode }) { return <div className="nav-group"><div className="nav-group-title">{title}</div>{children}</div>; }
function NavButton({ active, icon, label, onClick }: { active: boolean; icon: string; label: string; onClick: () => void }) { return <button className={`nav-item ${active ? 'active' : ''}`} aria-current={active ? 'page' : undefined} onClick={onClick}><span aria-hidden="true">{icon}</span>{label}</button>; }
function formatDate(value: string, locale: string) { const parsed = new Date(value); return Number.isNaN(parsed.valueOf()) ? '—' : new Intl.DateTimeFormat(locale, { dateStyle: 'medium', timeStyle: 'medium' }).format(parsed); }

export default App;

import { performAssertion, performRegistration, type CreationOptionsJson, type RequestOptionsJson } from './webauthn';
import type { Locale } from './i18n';
import { clearSessionClock, expireSession, observeSession } from './sessionClock';

export class ApiError extends Error {
  constructor(public status: number, public code: string, public traceId?: string) { super(code); }
}
export interface Principal { id: string; displayName: string }
export interface ManagedEnvironment { id: string; name: string; canonicalDns: string; defaultLocale: string; version: number }
export interface Rbac {
  roles: { id: string; name: string; builtInKind: string | null }[];
  permissions: { roleId: string; permission: string }[];
  scopes: { id: string; kind: number; value: string | null; includeDescendants: boolean }[];
  assignments: { id: string; principalId: string; roleId: string; scopeId: string }[];
  groupMappings: { id: string; groupSid: string; roleId: string; scopeId: string }[];
}
export interface AuditPage {
  items: { id: string; action: string; result: string; targetId?: string; occurredAt: string; correlationId: string; actorId?: string }[];
  nextCursor: string | null;
}
export interface Preference { locale: Locale }
export async function request<T>(path: string, init: RequestInit = {}, anonymous = false): Promise<T> {
  if (!path.startsWith('/api/v1/') || path.includes('\\') || path.includes('#')) throw new ApiError(0, 'InvalidApiPath');
  let response: Response;
  const startedAt = Date.now();
  try { response = await fetch(path, { ...init, credentials: 'same-origin', redirect: 'error', cache: 'no-store' }); }
  catch (e) {
    if (e instanceof DOMException && e.name === 'AbortError') throw e;
    throw new ApiError(0, 'NetworkUnavailable');
  }
  if (!response.ok) {
    let problem: { title?: string; traceId?: string } = {};
    try { problem = await response.json(); } catch { /* Never display raw server response HTML. */ }
    if (response.status === 401 && !anonymous) expireSession();
    throw new ApiError(response.status, problem.title ?? `Http${response.status}`, problem.traceId);
  }
  if (!observeSession(response, startedAt)) throw new ApiError(401, 'SessionInvalid');
  if (response.status === 204) return undefined as T;
  if (!response.headers.get('content-type')?.includes('application/json')) throw new ApiError(0, 'InvalidResponse');
  return response.json() as Promise<T>;
}
export const api = {
  get: <T>(path: string, signal?: AbortSignal) => request<T>(path, { signal }),
  post: async <T>(path: string, body: unknown = {}, anonymous = false) => {
    const { token } = await request<{ token: string }>('/api/v1/session/csrf');
    return request<T>(path, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-TOKEN': token }, body: JSON.stringify(body) }, anonymous);
  },
};
export const getSession = (signal?: AbortSignal, initialCheck = false) => request<Principal>('/api/v1/session/me', { signal }, initialCheck);
export const getEnvironments = async (signal?: AbortSignal) => (await api.get<{ items: ManagedEnvironment[] }>('/api/v1/environments', signal)).items;
const envPath = (env: string) => `/api/v1/environments/${encodeURIComponent(env)}`;
export const getAccess = (env: string, signal?: AbortSignal) => api.get<{ permissions: string[] }>(`${envPath(env)}/access`, signal);
export const getRbac = (env: string, signal?: AbortSignal) => api.get<Rbac>(`${envPath(env)}/rbac`, signal);
export const getAudit = (env: string, cursor?: string, signal?: AbortSignal) => api.get<AuditPage>(`${envPath(env)}/audit?limit=30${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`, signal);
export const getPreference = (signal?: AbortSignal) => api.get<Preference>('/api/v1/session/preferences', signal);
export const savePreference = (locale: Locale) => api.post<Preference>('/api/v1/session/preferences', { locale });
export const loginWindows = () => api.post<void>('/api/v1/session/windows', {}, true);
export const logout = async () => { await api.post<void>('/api/v1/session/logout'); clearSessionClock(); };
let ceremonyInProgress = false;
async function ceremony(run: () => Promise<void>) {
  if (ceremonyInProgress) throw new ApiError(409, 'CeremonyInProgress');
  ceremonyInProgress = true;
  try { await run(); }
  catch (e) {
    if (e instanceof ApiError) throw e;
    if (e instanceof DOMException && e.name === 'NotAllowedError') throw new ApiError(0, 'PasskeyCancelled');
    throw new ApiError(0, 'PasskeyUnavailable');
  }
  finally { ceremonyInProgress = false; }
}
export const loginEmergency = (username: string, password: string) => ceremony(async () => {
  const options = await api.post<RequestOptionsJson>('/api/v1/session/emergency/options', { username, password }, true);
  password = '';
  const assertion = await performAssertion(options);
  await api.post<void>('/api/v1/session/assertion', assertion, true);
});
export const enrollPasskey = (token: string) => ceremony(async () => {
  const options = await api.post<CreationOptionsJson>('/api/v1/session/passkeys/options', { token }, true);
  token = '';
  await api.post<void>('/api/v1/session/passkeys/complete', await performRegistration(options), true);
});
export const stepUp = () => ceremony(async () => {
  const options = await api.post<RequestOptionsJson>('/api/v1/session/step-up/options');
  await api.post<void>('/api/v1/session/assertion', await performAssertion(options));
});

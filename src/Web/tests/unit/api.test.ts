import { afterEach, describe, it, expect, vi } from 'vitest';
import { api, request, ApiError } from '../../src/api';
afterEach(() => { vi.unstubAllGlobals(); vi.useRealTimers(); });
describe('API trust boundaries', () => {
  it('uses current CSRF cookie handshake, same-origin credentials and no redirects', async () => {
    const fetch = vi.fn().mockResolvedValueOnce(new Response(JSON.stringify({ token: 'synthetic-csrf' }), { headers: { 'content-type': 'application/json' } }))
      .mockResolvedValueOnce(new Response(null, { status: 204 }));
    vi.stubGlobal('fetch', fetch);
    await api.post('/api/v1/session/logout');
    expect(fetch.mock.calls[0][0]).toBe('/api/v1/session/csrf');
    expect(fetch.mock.calls[1][1]).toMatchObject({ credentials: 'same-origin', redirect: 'error', cache: 'no-store',
      headers: { 'X-CSRF-TOKEN': 'synthetic-csrf' } });
  });
  it('does not send credentials to caller supplied absolute origins', async () => {
    const fetch = vi.fn(); vi.stubGlobal('fetch', fetch);
    await expect(request('https://attacker.invalid/api/v1/users')).rejects.toBeInstanceOf(ApiError);
    expect(fetch).not.toHaveBeenCalled();
  });
  it('invalidates client identity on protected 401 without exposing HTML error bodies', async () => {
    const dispatchEvent = vi.fn(); vi.stubGlobal('window', { dispatchEvent });
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('<script>secret</script>', { status: 401 })));
    await expect(request('/api/v1/environments')).rejects.toMatchObject({ code: 'Http401' });
    expect(dispatchEvent).toHaveBeenCalledOnce();
  });
  it('keeps a cancelled environment read distinguishable from network failure', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new DOMException('Aborted', 'AbortError')));
    await expect(request('/api/v1/environments')).rejects.toMatchObject({ name: 'AbortError' });
  });
  it('only suppresses session invalidation for an explicitly anonymous ceremony', async () => {
    const dispatchEvent = vi.fn(); vi.stubGlobal('window', { dispatchEvent });
    vi.stubGlobal('fetch', vi.fn().mockImplementation(() => Promise.resolve(new Response('{}', { status: 401 }))));
    await expect(request('/api/v1/session/assertion', {}, true)).rejects.toBeInstanceOf(ApiError);
    expect(dispatchEvent).not.toHaveBeenCalled();
    await expect(request('/api/v1/session/assertion')).rejects.toBeInstanceOf(ApiError);
    expect(dispatchEvent).toHaveBeenCalledOnce();
  });
  it('rejects an authenticated response already expired during transit before exposing its body', async () => {
    vi.useFakeTimers(); vi.setSystemTime(1000);
    const dispatchEvent = vi.fn(); vi.stubGlobal('window', { dispatchEvent });
    vi.stubGlobal('fetch', vi.fn().mockImplementation(async () => {
      vi.setSystemTime(2000);
      return new Response('{"displayName":"Expired person"}', { headers: { 'content-type': 'application/json', 'X-Session-Remaining-Ms': '500' } });
    }));
    await expect(request('/api/v1/session/me')).rejects.toMatchObject({ status: 401, code: 'SessionInvalid' });
    expect(dispatchEvent).toHaveBeenCalledOnce();
  });
});

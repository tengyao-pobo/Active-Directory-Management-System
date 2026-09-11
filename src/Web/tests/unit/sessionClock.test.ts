import { afterEach, expect, it, vi } from 'vitest';
import { clearSessionClock, observeSession } from '../../src/sessionClock';
afterEach(() => { clearSessionClock(); vi.useRealTimers(); vi.unstubAllGlobals(); });
it('clears a dormant screen at the server deadline, including network transit time', () => {
  vi.useFakeTimers(); vi.setSystemTime(1000);
  const dispatchEvent = vi.fn(); vi.stubGlobal('window', { dispatchEvent });
  observeSession(new Response(null, { headers: { 'X-Session-Remaining-Ms': '5000' } }), 500);
  vi.advanceTimersByTime(4499); expect(dispatchEvent).not.toHaveBeenCalled();
  vi.advanceTimersByTime(1); expect(dispatchEvent).toHaveBeenCalledOnce();
});
it('does not extend a deadline for a response without session metadata', () => {
  vi.useFakeTimers(); vi.setSystemTime(1000);
  const dispatchEvent = vi.fn(); vi.stubGlobal('window', { dispatchEvent });
  observeSession(new Response(null, { headers: { 'X-Session-Remaining-Ms': '500' } }), 1000);
  observeSession(new Response(), 1300);
  vi.advanceTimersByTime(500); expect(dispatchEvent).toHaveBeenCalledOnce();
});

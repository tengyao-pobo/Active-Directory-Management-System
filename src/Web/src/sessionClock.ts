let timer: ReturnType<typeof setTimeout> | undefined;
let deadline = 0;
export function clearSessionClock() {
  clearTimeout(timer);
  deadline = 0;
}
export function expireSession() {
  clearSessionClock();
  window.dispatchEvent(new Event('itmc:session-expired'));
}
export function observeSession(response: Response, startedAt: number) {
  const header = response.headers.get('X-Session-Remaining-Ms');
  if (header === null) return true;
  const remaining = Number(header);
  if (!Number.isFinite(remaining) || remaining <= 0) { expireSession(); return false; }
  clearTimeout(timer);
  // Count transit time conservatively; never extend beyond the server's deadline.
  deadline = startedAt + remaining;
  if (deadline <= Date.now()) { expireSession(); return false; }
  timer = setTimeout(expireSession, Math.max(0, deadline - Date.now()));
  return true;
}
if (typeof window !== 'undefined') {
  window.addEventListener('itmc:session-expired', clearSessionClock);
  window.addEventListener('pageshow', event => {
    if (deadline && (event.persisted || Date.now() >= deadline)) expireSession();
  });
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible' && deadline && Date.now() >= deadline) expireSession();
  });
}

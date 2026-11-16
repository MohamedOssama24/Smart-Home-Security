/**
 * One-time tokens arrive in the URL fragment ("#token=..."), which browsers never send to
 * servers nor in the Referer header. The token is read once and removed from the address
 * bar and history so it is not left in the browser history.
 */
export function takeTokenFromFragment(fragment: string | null): string | null {
  if (!fragment) {
    return null;
  }
  const token = new URLSearchParams(fragment).get('token');
  if (typeof history !== 'undefined' && typeof location !== 'undefined') {
    history.replaceState(history.state, '', location.pathname);
  }
  return token && /^[A-Za-z0-9_-]{10,200}$/.test(token) ? token : null;
}

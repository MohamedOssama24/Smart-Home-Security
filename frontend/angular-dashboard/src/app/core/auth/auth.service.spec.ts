import { TestBed } from '@angular/core/testing';
import { provideHttpClient, withInterceptors } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { authInterceptor } from './auth.interceptor';
import { AuthService } from './auth.service';
import { ME, token } from '../../testing/auth-fixtures';
import { nextRequest } from '../../testing/http';

describe('AuthService', () => {
  let auth: AuthService;
  let http: HttpTestingController;

  beforeEach(() => {
    document.cookie = 'XSRF-TOKEN=csrf-test';
    localStorage.clear();
    sessionStorage.clear();
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(withInterceptors([authInterceptor])),
        provideHttpClientTesting(),
        provideRouter([]),
      ],
    });
    auth = TestBed.inject(AuthService);
    http = TestBed.inject(HttpTestingController);
  });

  afterEach(() => http.verify());

  async function flushLogin(): Promise<void> {
    const login = auth.login('mario@example.test', 'Lungo-e-sicuro-42!');
    const request = await nextRequest(http, '/api/v1/auth/login');
    expect(request.request.body.email).toBe('mario@example.test');
    request.flush(token());
    const me = await nextRequest(http, '/api/v1/me');
    expect(me.request.headers.get('Authorization')).toBe('Bearer access-1');
    me.flush(ME);
    await login;
  }

  it('keeps the access token only in memory', async () => {
    await flushLogin();

    expect(auth.isAuthenticated()).toBe(true);
    expect(auth.accessToken()).toBe('access-1');
    expect(auth.me()?.email).toBe('mario@example.test');
    const stored = JSON.stringify({ ...localStorage }) + JSON.stringify({ ...sessionStorage }) + document.cookie;
    expect(stored).not.toContain('access-1');
  });

  it('fetches the CSRF cookie before the first state-changing call when missing', async () => {
    document.cookie = 'XSRF-TOKEN=; expires=Thu, 01 Jan 1970 00:00:00 GMT';
    const forgot = auth.forgotPassword('a@b.test');
    expect(http.match('/api/v1/auth/password/forgot')).toEqual([]);
    (await nextRequest(http, '/api/v1/auth/csrf')).flush(null);
    (await nextRequest(http, '/api/v1/auth/password/forgot')).flush(null, { status: 202, statusText: 'Accepted' });
    await forgot;
  });

  it('refresh is single-flight: concurrent callers share one request', async () => {
    const first = auth.refresh();
    const second = auth.refresh();
    expect(first).toBe(second);

    (await nextRequest(http, '/api/v1/auth/refresh')).flush(token('access-2'));
    (await nextRequest(http, '/api/v1/me')).flush(ME);

    expect(await first).toBe(true);
    expect(auth.accessToken()).toBe('access-2');
  });

  it('becomes anonymous when the refresh cookie is missing or revoked', async () => {
    const init = auth.init();
    (await nextRequest(http, '/api/v1/auth/refresh')).flush(
      { code: 'INVALID_REFRESH_TOKEN' },
      { status: 401, statusText: 'Unauthorized' },
    );
    await init;

    expect(auth.status()).toBe('anonymous');
    expect(auth.accessToken()).toBeNull();
  });

  it('logout revokes the session on the server and forgets it locally', async () => {
    await flushLogin();
    const logout = auth.logout();
    (await nextRequest(http, '/api/v1/auth/logout')).flush(null, { status: 204, statusText: 'No Content' });
    await logout;

    expect(auth.isAuthenticated()).toBe(false);
    expect(auth.me()).toBeNull();
  });

  it('exposes permissions for UI decisions', async () => {
    await flushLogin();
    expect(auth.hasPermission('agent:enroll')).toBe(true);
    expect(auth.hasPermission('role:manage')).toBe(false);
  });
});

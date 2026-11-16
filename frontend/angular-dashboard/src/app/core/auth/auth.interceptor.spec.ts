import { TestBed } from '@angular/core/testing';
import { HttpClient, provideHttpClient, withInterceptors } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { Router, provideRouter } from '@angular/router';
import { firstValueFrom } from 'rxjs';
import { authInterceptor } from './auth.interceptor';
import { AuthService } from './auth.service';
import { ME, token } from '../../testing/auth-fixtures';
import { nextRequest, settle } from '../../testing/http';

describe('authInterceptor', () => {
  let http: HttpClient;
  let backend: HttpTestingController;
  let auth: AuthService;

  beforeEach(async () => {
    document.cookie = 'XSRF-TOKEN=csrf-test';
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(withInterceptors([authInterceptor])),
        provideHttpClientTesting(),
        provideRouter([]),
      ],
    });
    http = TestBed.inject(HttpClient);
    backend = TestBed.inject(HttpTestingController);
    auth = TestBed.inject(AuthService);

    // signed-in state
    const login = auth.login('mario@example.test', 'x');
    (await nextRequest(backend, '/api/v1/auth/login')).flush(token('old-token'));
    (await nextRequest(backend, '/api/v1/me')).flush(ME);
    await login;
  });

  afterEach(() => backend.verify());

  it('adds the bearer token to API calls only', () => {
    http.get('/api/v1/homes').subscribe();
    http.get('https://cdn.example.com/file.json').subscribe();

    expect(backend.expectOne('/api/v1/homes').request.headers.get('Authorization')).toBe('Bearer old-token');
    expect(backend.expectOne('https://cdn.example.com/file.json').request.headers.has('Authorization')).toBe(false);
  });

  it('never sends the access token to the cookie-based auth endpoints', () => {
    http.post('/api/v1/auth/refresh', {}).subscribe();
    expect(backend.expectOne('/api/v1/auth/refresh').request.headers.has('Authorization')).toBe(false);
  });

  it('refreshes once on 401 and retries the request', async () => {
    const result = firstValueFrom(http.get<string[]>('/api/v1/homes'));
    backend.expectOne('/api/v1/homes').flush(null, { status: 401, statusText: 'Unauthorized' });

    (await nextRequest(backend, '/api/v1/auth/refresh')).flush(token('new-token'));
    (await nextRequest(backend, '/api/v1/me')).flush(ME);

    const retried = await nextRequest(backend, '/api/v1/homes');
    expect(retried.request.headers.get('Authorization')).toBe('Bearer new-token');
    retried.flush(['home']);
    expect(await result).toEqual(['home']);
  });

  it('closes the session and goes to login when the refresh fails', async () => {
    const navigate = vi.spyOn(TestBed.inject(Router), 'navigate').mockResolvedValue(true);
    const result = firstValueFrom(http.get('/api/v1/homes')).catch((e: unknown) => e);
    backend.expectOne('/api/v1/homes').flush(null, { status: 401, statusText: 'Unauthorized' });
    (await nextRequest(backend, '/api/v1/auth/refresh')).flush(null, { status: 401, statusText: 'Unauthorized' });

    const error = (await result) as { status: number };
    expect(error.status).toBe(401);
    expect(auth.isAuthenticated()).toBe(false);
    expect(navigate).toHaveBeenCalledWith(['/login'], { queryParams: { expired: 1 } });
  });

  it('does not refresh on 403 (missing permission)', async () => {
    const result = firstValueFrom(http.post('/api/v1/homes', {})).catch((e: unknown) => e);
    backend.expectOne('/api/v1/homes').flush({ code: 'FORBIDDEN' }, { status: 403, statusText: 'Forbidden' });
    expect(((await result) as { status: number }).status).toBe(403);
    await settle();
    backend.expectNone('/api/v1/auth/refresh');
  });
});

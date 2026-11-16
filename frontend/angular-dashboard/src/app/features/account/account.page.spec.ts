import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { signal } from '@angular/core';
import { Router, provideRouter } from '@angular/router';
import { UserSession } from '../../core/auth/auth.models';
import { AuthService } from '../../core/auth/auth.service';
import { ME } from '../../testing/auth-fixtures';
import { translocoTesting } from '../../testing/transloco-testing';
import { AccountPage } from './account.page';

const SESSIONS: UserSession[] = [
  { id: 's1', deviceLabel: 'Firefox su Linux', userAgent: 'Mozilla/5.0', ipAddress: '10.0.0.1', createdAt: '2026-11-16T09:00:00Z', lastUsedAt: '2026-11-16T10:00:00Z', expiresAt: '2026-11-30T09:00:00Z', current: true },
  { id: 's2', deviceLabel: null, userAgent: null, ipAddress: '10.0.0.2', createdAt: '2026-11-15T09:00:00Z', lastUsedAt: '2026-11-15T10:00:00Z', expiresAt: '2026-11-29T09:00:00Z', current: false },
];

const settle = () => new Promise((resolve) => setTimeout(resolve));

describe('AccountPage', () => {
  let http: HttpTestingController;
  const auth = { me: signal(ME), clear: vi.fn() };

  async function setup() {
    await TestBed.configureTestingModule({
      imports: [AccountPage, translocoTesting()],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideRouter([]),
        { provide: AuthService, useValue: auth },
      ],
    }).compileComponents();
    http = TestBed.inject(HttpTestingController);
    const fixture = TestBed.createComponent(AccountPage);
    fixture.detectChanges();
    http.expectOne('/api/v1/me/sessions').flush(SESSIONS);
    await settle();
    await fixture.whenStable();
    return fixture;
  }

  beforeEach(() => auth.clear.mockReset());
  afterEach(() => http.verify());

  it('lists sessions and marks the current one (which cannot be revoked individually)', async () => {
    const fixture = await setup();
    const rows = (fixture.nativeElement as HTMLElement).querySelectorAll('[data-testid="sessions"] tbody tr');

    expect(rows.length).toBe(2);
    expect(rows[0].textContent).toContain('Questa sessione');
    expect(rows[0].querySelector('button')).toBeNull();
    expect(rows[1].textContent).toContain('Dispositivo sconosciuto');
  });

  it('revokes a single other session and reloads the list', async () => {
    const fixture = await setup();
    const revoke = fixture.componentInstance.revoke(SESSIONS[1]);

    http.expectOne({ method: 'DELETE', url: '/api/v1/me/sessions/s2' }).flush(null, { status: 204, statusText: 'No Content' });
    await settle();
    http.expectOne('/api/v1/me/sessions').flush([SESSIONS[0]]);
    await revoke;

    expect(fixture.componentInstance.sessions().map((s) => s.id)).toEqual(['s1']);
  });

  it('"sign out everywhere" revokes the current session too and leaves the page', async () => {
    const fixture = await setup();
    const navigate = vi.spyOn(TestBed.inject(Router), 'navigateByUrl').mockResolvedValue(true);
    const action = fixture.componentInstance.revokeAll();

    const request = http.expectOne('/api/v1/me/sessions/revoke-all');
    expect(request.request.body).toEqual({ includeCurrent: true });
    request.flush({ revoked: 2 });
    await action;

    expect(auth.clear).toHaveBeenCalled();
    expect(navigate).toHaveBeenCalledWith('/login');
  });

  it('shows the backend error when the current password is wrong', async () => {
    const fixture = await setup();
    fixture.componentInstance.passwordForm.setValue({ current: 'sbagliata', next: 'Nuova-password-lunga-7' });
    const change = fixture.componentInstance.changePassword();

    http
      .expectOne('/api/v1/me/password')
      .flush({ code: 'INVALID_CURRENT_PASSWORD' }, { status: 400, statusText: 'Bad Request' });
    await change;
    await fixture.whenStable();

    expect(fixture.componentInstance.passwordProblem()?.code).toBe('INVALID_CURRENT_PASSWORD');
    expect((fixture.nativeElement as HTMLElement).querySelector('[role="alert"]')?.textContent).toContain(
      'password attuale',
    );
  });
});

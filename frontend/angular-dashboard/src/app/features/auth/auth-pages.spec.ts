import { TestBed } from '@angular/core/testing';
import { HttpErrorResponse } from '@angular/common/http';
import { Type } from '@angular/core';
import { ActivatedRoute, Router, convertToParamMap, provideRouter } from '@angular/router';
import { AuthService } from '../../core/auth/auth.service';
import { translocoTesting } from '../../testing/transloco-testing';
import { LoginPage } from './login.page';
import { RegisterPage } from './register.page';
import { VerifyEmailPage } from './verify-email.page';
import { takeTokenFromFragment } from './token-from-fragment';

function route(fragment: string | null = null, query: Record<string, string> = {}) {
  return { snapshot: { fragment, queryParamMap: convertToParamMap(query) } };
}

function fill(element: HTMLElement, selector: string, value: string): void {
  const input = element.querySelector(selector) as HTMLInputElement;
  input.value = value;
  input.dispatchEvent(new Event('input'));
  input.dispatchEvent(new Event('blur'));
}

const settle = () => new Promise((resolve) => setTimeout(resolve));

describe('authentication pages', () => {
  const auth = {
    login: vi.fn(),
    register: vi.fn(),
    verifyEmail: vi.fn(),
    resendVerification: vi.fn(),
  };

  async function setup<T>(component: Type<T>, activated = route()) {
    await TestBed.configureTestingModule({
      imports: [component, translocoTesting()],
      providers: [
        provideRouter([]),
        { provide: AuthService, useValue: auth },
        { provide: ActivatedRoute, useValue: activated },
      ],
    }).compileComponents();
    const fixture = TestBed.createComponent(component);
    await fixture.whenStable();
    return fixture;
  }

  beforeEach(() => vi.resetAllMocks());

  it('login navigates to the requested internal page', async () => {
    auth.login.mockResolvedValue(undefined);
    const fixture = await setup(LoginPage, route(null, { returnUrl: '/account' }));
    const navigate = vi.spyOn(TestBed.inject(Router), 'navigateByUrl').mockResolvedValue(true);
    const element = fixture.nativeElement as HTMLElement;

    fill(element, '#email', 'mario@example.test');
    fill(element, '#password', 'Lungo-e-sicuro-42!');
    await fixture.componentInstance.submit();

    expect(auth.login).toHaveBeenCalledWith('mario@example.test', 'Lungo-e-sicuro-42!');
    expect(navigate).toHaveBeenCalledWith('/account');
  });

  it('login shows a generic message and clears the password on failure', async () => {
    auth.login.mockRejectedValue(
      new HttpErrorResponse({ status: 401, error: { code: 'INVALID_CREDENTIALS' } }),
    );
    const fixture = await setup(LoginPage);
    const element = fixture.nativeElement as HTMLElement;
    fill(element, '#email', 'mario@example.test');
    fill(element, '#password', 'sbagliata');

    await fixture.componentInstance.submit();
    await fixture.whenStable();

    expect(element.querySelector('[data-testid="login-error"]')?.textContent).toContain('Email o password non corrette');
    expect((element.querySelector('#password') as HTMLInputElement).value).toBe('');
  });

  it('register validates the password length before calling the API', async () => {
    const fixture = await setup(RegisterPage);
    const element = fixture.nativeElement as HTMLElement;
    fill(element, '#displayName', 'Mario');
    fill(element, '#email', 'mario@example.test');
    fill(element, '#password', 'corta');

    await fixture.componentInstance.submit();
    fixture.changeDetectorRef.markForCheck();
    await fixture.whenStable();

    expect(auth.register).not.toHaveBeenCalled();
    expect(element.querySelector('[data-testid="password-too-short"]')).not.toBeNull();
  });

  it('register shows the same confirmation for every address', async () => {
    auth.register.mockResolvedValue(undefined);
    const fixture = await setup(RegisterPage);
    const element = fixture.nativeElement as HTMLElement;
    fill(element, '#displayName', 'Mario');
    fill(element, '#email', 'mario@example.test');
    fill(element, '#password', 'Lungo-e-sicuro-42!');

    await fixture.componentInstance.submit();
    await fixture.whenStable();

    expect(auth.register).toHaveBeenCalledWith(
      expect.objectContaining({ email: 'mario@example.test', accountType: 'INDIVIDUAL', locale: 'it' }),
    );
    expect(element.querySelector('[data-testid="register-done"]')).not.toBeNull();
  });

  it('register lists the password policy violations returned by the backend', async () => {
    auth.register.mockRejectedValue(
      new HttpErrorResponse({ status: 400, error: { code: 'PASSWORD_POLICY', violations: ['PASSWORD_TOO_COMMON'] } }),
    );
    const fixture = await setup(RegisterPage);
    const element = fixture.nativeElement as HTMLElement;
    fill(element, '#displayName', 'Mario');
    fill(element, '#email', 'mario@example.test');
    fill(element, '#password', 'password1234');

    await fixture.componentInstance.submit();
    await fixture.whenStable();

    expect(element.querySelector('[data-testid="register-error"]')?.textContent).toContain('tra quelle più usate');
  });

  it('verify-email reads the token from the fragment and confirms it', async () => {
    auth.verifyEmail.mockResolvedValue(undefined);
    const fixture = await setup(VerifyEmailPage, route('token=shsc_et_abcdefghijklmnop'));
    await settle();
    await fixture.whenStable();

    expect(auth.verifyEmail).toHaveBeenCalledTimes(1);
    expect(auth.verifyEmail).toHaveBeenCalledWith('shsc_et_abcdefghijklmnop');
    expect((fixture.nativeElement as HTMLElement).querySelector('[data-testid="verify-done"]')).not.toBeNull();
  });

  it('verify-email without token shows an error and calls nothing', async () => {
    const fixture = await setup(VerifyEmailPage, route(null));
    await settle();
    await fixture.whenStable();

    expect(auth.verifyEmail).not.toHaveBeenCalled();
    expect((fixture.nativeElement as HTMLElement).querySelector('[data-testid="verify-error"]')).not.toBeNull();
  });

  it('tokens are taken from the fragment, validated and removed from the address bar', () => {
    history.replaceState(null, '', '/verify-email#token=shsc_et_abcdefghijklmnop');
    expect(takeTokenFromFragment('token=shsc_et_abcdefghijklmnop')).toBe('shsc_et_abcdefghijklmnop');
    expect(location.hash).toBe('');
    expect(takeTokenFromFragment('token=<script>')).toBeNull();
    expect(takeTokenFromFragment(null)).toBeNull();
  });
});

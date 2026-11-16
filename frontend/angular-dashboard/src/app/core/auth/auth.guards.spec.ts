import { TestBed } from '@angular/core/testing';
import { ActivatedRouteSnapshot, Router, RouterStateSnapshot, UrlTree, provideRouter } from '@angular/router';
import { AuthService } from './auth.service';
import { authGuard, guestGuard, safeReturnUrl } from './auth.guards';

describe('auth guards', () => {
  let authenticated = false;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideRouter([]),
        { provide: AuthService, useValue: { isAuthenticated: () => authenticated } },
      ],
    });
  });

  function run(guard: typeof authGuard, url = '/homes'): boolean | UrlTree {
    return TestBed.runInInjectionContext(
      () => guard({} as ActivatedRouteSnapshot, { url } as RouterStateSnapshot) as boolean | UrlTree,
    );
  }

  it('sends anonymous users to login, remembering the page', () => {
    authenticated = false;
    const result = run(authGuard, '/homes/42') as UrlTree;
    expect(TestBed.inject(Router).serializeUrl(result)).toBe('/login?returnUrl=%2Fhomes%2F42');
  });

  it('lets signed-in users through and keeps them away from login', () => {
    authenticated = true;
    expect(run(authGuard)).toBe(true);
    expect(TestBed.inject(Router).serializeUrl(run(guestGuard) as UrlTree)).toBe('/homes');
  });

  it('only accepts internal return URLs (no open redirect)', () => {
    expect(safeReturnUrl('/account')).toBe('/account');
    expect(safeReturnUrl('https://evil.example')).toBe('/homes');
    expect(safeReturnUrl('//evil.example')).toBe('/homes');
    expect(safeReturnUrl('/\\evil.example')).toBe('/homes');
    expect(safeReturnUrl(null)).toBe('/homes');
  });
});

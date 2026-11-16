import { HttpErrorResponse, HttpInterceptorFn, HttpRequest } from '@angular/common/http';
import { inject } from '@angular/core';
import { Router } from '@angular/router';
import { catchError, from, switchMap, throwError } from 'rxjs';
import { AUTH_API, AuthService } from './auth.service';

/** Only same-origin API calls carry the access token (never third-party URLs). */
function isApiRequest(request: HttpRequest<unknown>): boolean {
  return request.url.startsWith('/api/');
}

function isAuthEndpoint(request: HttpRequest<unknown>): boolean {
  return request.url.startsWith(`${AUTH_API}/`);
}

function withToken(request: HttpRequest<unknown>, token: string | null): HttpRequest<unknown> {
  return token ? request.clone({ setHeaders: { Authorization: `Bearer ${token}` } }) : request;
}

/**
 * Adds the in-memory access token to API calls. On a 401 caused by an expired access token
 * it refreshes once (single-flight) and retries the request; if the refresh fails the session
 * is closed and the user is sent to the login page.
 */
export const authInterceptor: HttpInterceptorFn = (request, next) => {
  if (!isApiRequest(request) || isAuthEndpoint(request)) {
    return next(request);
  }
  const auth = inject(AuthService);
  const router = inject(Router);

  return next(withToken(request, auth.accessToken())).pipe(
    catchError((error: unknown) => {
      if (!(error instanceof HttpErrorResponse) || error.status !== 401 || !auth.accessToken()) {
        return throwError(() => error);
      }
      return from(auth.refresh()).pipe(
        switchMap((refreshed) => {
          if (!refreshed) {
            void router.navigate(['/login'], { queryParams: { expired: 1 } });
            return throwError(() => error);
          }
          return next(withToken(request, auth.accessToken()));
        }),
      );
    }),
  );
};

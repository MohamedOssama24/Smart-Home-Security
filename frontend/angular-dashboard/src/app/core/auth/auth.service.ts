import { HttpClient } from '@angular/common/http';
import { Injectable, computed, inject, signal } from '@angular/core';
import { Observable, firstValueFrom } from 'rxjs';
import { Me, RegisterRequest, TokenResponse, hasTenantWidePermission } from './auth.models';

export type AuthStatus = 'unknown' | 'authenticated' | 'anonymous';

export const AUTH_API = '/api/v1/auth';

/**
 * Session state of the dashboard.
 * - The access token lives ONLY in memory (a signal): never localStorage/sessionStorage.
 * - The refresh token is an HttpOnly cookie the code cannot read; it is rotated by the
 *   backend at every refresh.
 * - The CSRF token is the XSRF-TOKEN cookie, sent back by Angular's HttpClient as the
 *   X-XSRF-TOKEN header on mutating same-origin requests.
 * - Refreshes are single-flight in the tab and serialized across tabs (Web Locks API),
 *   so two tabs do not present the same refresh token (which would look like token theft).
 */
@Injectable({ providedIn: 'root' })
export class AuthService {
  private readonly http = inject(HttpClient);

  private readonly token = signal<string | null>(null);
  private readonly profile = signal<Me | null>(null);
  private readonly state = signal<AuthStatus>('unknown');
  private refreshing: Promise<boolean> | null = null;

  readonly status = this.state.asReadonly();
  readonly me = this.profile.asReadonly();
  readonly isAuthenticated = computed(() => this.state() === 'authenticated');

  /** Current access token (in memory), for the HTTP interceptor. */
  accessToken(): string | null {
    return this.token();
  }

  hasPermission(permission: string): boolean {
    return this.profile()?.permissions.includes(permission) ?? false;
  }

  /**
   * UI hint only (the backend decides): the user holds the permission and at least one
   * tenant-wide role. The profile lists permissions as a union, so with mixed roles this may
   * show an action the backend then refuses with 403.
   */
  hasTenantWidePermission(permission: string): boolean {
    return hasTenantWidePermission(this.profile(), permission);
  }

  /** Called at startup: restores the session from the refresh cookie, if any. */
  async init(): Promise<void> {
    try {
      await this.ensureCsrfToken();
    } catch {
      // backend unreachable: stay anonymous, pages will show the error
    }
    const restored = await this.refresh();
    if (!restored) {
      this.state.set('anonymous');
    }
  }

  async login(email: string, password: string): Promise<void> {
    await this.ensureCsrfToken();
    const response = await firstValueFrom(
      this.http.post<TokenResponse>(`${AUTH_API}/login`, { email, password, deviceLabel: deviceLabel() }),
    );
    await this.startSession(response);
  }

  async register(request: RegisterRequest): Promise<void> {
    await this.ensureCsrfToken();
    await firstValueFrom(this.http.post<void>(`${AUTH_API}/register`, request));
  }

  async verifyEmail(token: string): Promise<void> {
    await this.ensureCsrfToken();
    await firstValueFrom(this.http.post<void>(`${AUTH_API}/verify-email`, { token }));
  }

  async resendVerification(email: string): Promise<void> {
    await this.ensureCsrfToken();
    await firstValueFrom(this.http.post<void>(`${AUTH_API}/verify-email/resend`, { email }));
  }

  async forgotPassword(email: string): Promise<void> {
    await this.ensureCsrfToken();
    await firstValueFrom(this.http.post<void>(`${AUTH_API}/password/forgot`, { email }));
  }

  async resetPassword(token: string, newPassword: string): Promise<void> {
    await this.ensureCsrfToken();
    await firstValueFrom(this.http.post<void>(`${AUTH_API}/password/reset`, { token, newPassword }));
  }

  /** Invited users choose their password; the account is then active (sign-in still required). */
  async acceptInvitation(token: string, newPassword: string): Promise<void> {
    await this.ensureCsrfToken();
    await firstValueFrom(this.http.post<void>(`${AUTH_API}/invitation/accept`, { token, newPassword }));
  }

  async logout(): Promise<void> {
    try {
      await this.ensureCsrfToken();
      await firstValueFrom(this.http.post<void>(`${AUTH_API}/logout`, {}));
    } finally {
      this.clear();
    }
  }

  /** Reloads the profile (e.g. after a role change or a profile update). */
  async reloadProfile(): Promise<void> {
    this.profile.set(await firstValueFrom(this.http.get<Me>('/api/v1/me')));
  }

  /**
   * Obtains a new access token with the refresh cookie. Returns false (and clears the
   * session) when the refresh token is missing, expired, revoked or reused.
   */
  refresh(): Promise<boolean> {
    if (!this.refreshing) {
      this.refreshing = withCrossTabLock(() => this.doRefresh()).finally(() => {
        this.refreshing = null;
      });
    }
    return this.refreshing;
  }

  /** Forgets the session locally (the backend session is revoked by logout or already invalid). */
  clear(): void {
    this.token.set(null);
    this.profile.set(null);
    this.state.set('anonymous');
  }

  private async doRefresh(): Promise<boolean> {
    try {
      const response = await firstValueFrom(this.http.post<TokenResponse>(`${AUTH_API}/refresh`, {}));
      await this.startSession(response);
      return true;
    } catch {
      this.clear();
      return false;
    }
  }

  private async startSession(response: TokenResponse): Promise<void> {
    this.token.set(response.accessToken);
    this.profile.set(await firstValueFrom(this.http.get<Me>('/api/v1/me')));
    this.state.set('authenticated');
  }

  /** The backend issues the XSRF-TOKEN cookie on demand; Angular sends it back as a header. */
  private async ensureCsrfToken(): Promise<void> {
    if (!hasCookie('XSRF-TOKEN')) {
      await firstValueFrom(this.csrf());
    }
  }

  private csrf(): Observable<void> {
    return this.http.get<void>(`${AUTH_API}/csrf`);
  }
}

function hasCookie(name: string): boolean {
  return document.cookie.split(';').some((part) => part.trim().startsWith(`${name}=`));
}

function deviceLabel(): string {
  const agent = navigator.userAgent;
  const browser = /Edg\//.test(agent)
    ? 'Edge'
    : /Firefox\//.test(agent)
      ? 'Firefox'
      : /Chrome\//.test(agent)
        ? 'Chrome'
        : /Safari\//.test(agent)
          ? 'Safari'
          : 'Browser';
  const os = /Windows/.test(agent)
    ? 'Windows'
    : /Android/.test(agent)
      ? 'Android'
      : /iPhone|iPad/.test(agent)
        ? 'iOS'
        : /Mac OS X/.test(agent)
          ? 'macOS'
          : /Linux/.test(agent)
            ? 'Linux'
            : '';
  return os ? `${browser} · ${os}` : browser;
}

interface LockManagerLike {
  request<T>(name: string, callback: () => Promise<T>): Promise<T>;
}

/** Serializes the refresh across tabs when the Web Locks API is available. */
function withCrossTabLock<T>(action: () => Promise<T>): Promise<T> {
  const locks = (navigator as Navigator & { locks?: LockManagerLike }).locks;
  return locks?.request ? locks.request('shsc-refresh', action) : action();
}

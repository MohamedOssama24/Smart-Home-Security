import { HttpClient } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { Me, UserSession } from './auth.models';

/** The signed-in user's own account: profile, password, sessions. */
@Injectable({ providedIn: 'root' })
export class AccountApi {
  private readonly http = inject(HttpClient);

  updateProfile(displayName: string, locale: 'it' | 'en'): Observable<Me> {
    return this.http.patch<Me>('/api/v1/me', { displayName, locale });
  }

  changePassword(currentPassword: string, newPassword: string): Observable<void> {
    return this.http.post<void>('/api/v1/me/password', { currentPassword, newPassword });
  }

  sessions(): Observable<UserSession[]> {
    return this.http.get<UserSession[]>('/api/v1/me/sessions');
  }

  revokeSession(id: string): Observable<void> {
    return this.http.delete<void>(`/api/v1/me/sessions/${encodeURIComponent(id)}`);
  }

  revokeAllSessions(includeCurrent: boolean): Observable<{ revoked: number }> {
    return this.http.post<{ revoked: number }>('/api/v1/me/sessions/revoke-all', { includeCurrent });
  }
}

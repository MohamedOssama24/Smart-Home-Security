import { HttpClient } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { ScopeType } from '../auth/auth.models';

export type UserStatus = 'ACTIVE' | 'PENDING_VERIFICATION' | 'DISABLED';

export interface UserRoleAssignment {
  id: string;
  role: string;
  scopeType: ScopeType;
  scopeId: string | null;
  grantedBy: string | null;
  grantedAt: string;
}

export interface TenantUser {
  id: string;
  email: string;
  displayName: string;
  locale: 'it' | 'en';
  status: UserStatus;
  invitationPending: boolean;
  createdAt: string;
  lastLoginAt: string | null;
  roles: UserRoleAssignment[];
}

export interface RoleDefinition {
  code: string;
  description: string;
  assignableScopes: ScopeType[];
  permissions: string[];
}

export interface InviteUserRequest {
  email: string;
  displayName: string;
  locale: 'it' | 'en';
  role: string;
  scopeType: ScopeType;
  scopeId?: string | null;
}

export interface RoleRequest {
  role: string;
  scopeType: ScopeType;
  scopeId?: string | null;
}

/** Users of the current tenant (backend: /api/v1/users, /api/v1/roles). */
@Injectable({ providedIn: 'root' })
export class UsersApi {
  private readonly http = inject(HttpClient);

  list(): Observable<TenantUser[]> {
    return this.http.get<TenantUser[]>('/api/v1/users');
  }

  invite(request: InviteUserRequest): Observable<TenantUser> {
    return this.http.post<TenantUser>('/api/v1/users', request);
  }

  resendInvitation(userId: string): Observable<void> {
    return this.http.post<void>(`/api/v1/users/${encodeURIComponent(userId)}/invitation`, {});
  }

  update(userId: string, changes: { displayName?: string; status?: 'ACTIVE' | 'DISABLED' }): Observable<TenantUser> {
    return this.http.patch<TenantUser>(`/api/v1/users/${encodeURIComponent(userId)}`, changes);
  }

  roles(): Observable<RoleDefinition[]> {
    return this.http.get<RoleDefinition[]>('/api/v1/roles');
  }

  assignRole(userId: string, request: RoleRequest): Observable<{ id: string }> {
    return this.http.post<{ id: string }>(`/api/v1/users/${encodeURIComponent(userId)}/roles`, request);
  }

  removeRole(userId: string, assignmentId: string): Observable<void> {
    return this.http.delete<void>(
      `/api/v1/users/${encodeURIComponent(userId)}/roles/${encodeURIComponent(assignmentId)}`,
    );
  }
}

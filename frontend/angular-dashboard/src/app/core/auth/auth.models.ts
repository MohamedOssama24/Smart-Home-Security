/** DTOs of the authentication API (backend: /api/v1/auth, /api/v1/me). */

export interface TokenResponse {
  accessToken: string;
  tokenType: 'Bearer';
  expiresIn: number;
  expiresAt: string;
  sessionId: string;
}

export type ScopeType = 'PLATFORM' | 'TENANT' | 'ORGANIZATION' | 'CUSTOMER' | 'HOME';

/** Scopes that cover the whole tenant (HOME and CUSTOMER are limited to some resources). */
export const TENANT_WIDE_SCOPES: readonly ScopeType[] = ['PLATFORM', 'TENANT', 'ORGANIZATION'];

export interface RoleAssignment {
  id: string;
  role: string;
  scopeType: ScopeType;
  scopeId: string | null;
}

export interface Me {
  id: string;
  email: string;
  displayName: string;
  locale: 'it' | 'en';
  status: string;
  emailVerifiedAt: string | null;
  tenant: { id: string; type: 'INDIVIDUAL' | 'BUSINESS' | 'PLATFORM'; name: string; organizationId: string | null };
  roles: RoleAssignment[];
  permissions: string[];
  sessionId: string;
}

export interface UserSession {
  id: string;
  deviceLabel: string | null;
  userAgent: string | null;
  ipAddress: string | null;
  createdAt: string;
  lastUsedAt: string;
  expiresAt: string;
  current: boolean;
}

export type AccountType = 'INDIVIDUAL' | 'BUSINESS';

export interface RegisterRequest {
  email: string;
  password: string;
  displayName: string;
  locale: 'it' | 'en';
  accountType: AccountType;
  organizationName?: string;
}

/** Minimum length enforced by the backend password policy (the backend is authoritative). */
export const PASSWORD_MIN_LENGTH = 12;
export const PASSWORD_MAX_LENGTH = 128;

/** UI hint: the user holds the permission and at least one tenant-wide role (see AuthService). */
export function hasTenantWidePermission(me: Me | null, permission: string): boolean {
  return (
    !!me && me.permissions.includes(permission) && me.roles.some((r) => TENANT_WIDE_SCOPES.includes(r.scopeType))
  );
}

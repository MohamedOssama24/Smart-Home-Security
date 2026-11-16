import { Me, TokenResponse } from '../core/auth/auth.models';

export const ME: Me = {
  id: 'u1',
  email: 'mario@example.test',
  displayName: 'Mario',
  locale: 'it',
  status: 'ACTIVE',
  emailVerifiedAt: '2026-11-16T10:00:00Z',
  tenant: { id: 't1', type: 'INDIVIDUAL', name: 'Mario', organizationId: null },
  roles: [{ id: 'r1', role: 'CUSTOMER', scopeType: 'TENANT', scopeId: null }],
  permissions: ['home:read', 'home:write', 'agent:enroll', 'agent:read', 'agent:revoke'],
  sessionId: 's1',
};

export function token(value = 'access-1'): TokenResponse {
  return { accessToken: value, tokenType: 'Bearer', expiresIn: 900, expiresAt: '2026-11-16T10:15:00Z', sessionId: 's1' };
}

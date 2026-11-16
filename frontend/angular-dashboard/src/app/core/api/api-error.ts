import { HttpErrorResponse } from '@angular/common/http';

/** Error codes the UI knows how to explain (keys under "errors." in the i18n files). */
const KNOWN_CODES = new Set([
  'INVALID_CREDENTIALS',
  'EMAIL_NOT_VERIFIED',
  'TOO_MANY_ATTEMPTS',
  'PASSWORD_POLICY',
  'INVALID_TOKEN',
  'INVALID_CURRENT_PASSWORD',
  'PASSWORD_UNCHANGED',
  'ORGANIZATION_NAME_REQUIRED',
  'VALIDATION_FAILED',
  'CSRF_INVALID',
  'FORBIDDEN',
  'NOT_FOUND',
  'TOKEN_ALREADY_USED',
  'UNAUTHENTICATED',
  'INVALID_REFRESH_TOKEN',
  'PLAN_LIMIT_REACHED',
  'EMAIL_ALREADY_REGISTERED',
  'NETWORK_OVERLAP',
  'NETWORK_NOT_PRIVATE',
  'NETWORK_TOO_LARGE',
  'NETWORK_ALREADY_AUTHORIZED',
  'NETWORK_NOT_AUTHORIZED',
  'ATTESTATION_REQUIRED',
  'ATTESTATION_OUTDATED',
  'CUSTOMER_HAS_HOMES',
  'HOME_HAS_ACTIVE_AGENTS',
  'LAST_ADMIN',
  'CANNOT_DISABLE_SELF',
  'INVALID_CIDR',
  'INVALID_TIMEZONE',
  'INVALID_VAT_NUMBER',
  'INVALID_CUSTOMER',
  'INVITATION_NOT_PENDING',
  'BUSINESS_TENANT_REQUIRED',
  'INVALID_SCOPE',
  'ROLE_ALREADY_ASSIGNED',
  'INVALID_STATUS',
  'UNKNOWN_ROLE',
]);

export interface ApiProblem {
  /** Translation key, e.g. "errors.INVALID_CREDENTIALS". */
  messageKey: string;
  code: string;
  status: number;
  /** Password policy violations (codes), when present. */
  violations: string[];
  retryAfterSeconds?: number;
}

/** Maps an HTTP error (RFC 9457 Problem Details) to something the UI can display. */
export function toApiProblem(error: unknown): ApiProblem {
  if (!(error instanceof HttpErrorResponse)) {
    return { messageKey: 'errors.GENERIC', code: 'GENERIC', status: 0, violations: [] };
  }
  if (error.status === 0) {
    return { messageKey: 'errors.NETWORK', code: 'NETWORK', status: 0, violations: [] };
  }
  const body = (error.error ?? {}) as { code?: unknown; violations?: unknown; retryAfterSeconds?: unknown };
  const code = typeof body.code === 'string' ? body.code : 'GENERIC';
  const violations = Array.isArray(body.violations)
    ? body.violations.filter((v): v is string => typeof v === 'string')
    : [];
  return {
    messageKey: KNOWN_CODES.has(code) ? `errors.${code}` : 'errors.GENERIC',
    code,
    status: error.status,
    violations,
    retryAfterSeconds: typeof body.retryAfterSeconds === 'number' ? body.retryAfterSeconds : undefined,
  };
}

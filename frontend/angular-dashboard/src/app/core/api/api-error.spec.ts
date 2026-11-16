import { HttpErrorResponse } from '@angular/common/http';
import { toApiProblem } from './api-error';

describe('toApiProblem', () => {
  it('maps known problem codes to translation keys', () => {
    const problem = toApiProblem(
      new HttpErrorResponse({ status: 401, error: { code: 'INVALID_CREDENTIALS', detail: 'x' } }),
    );
    expect(problem).toMatchObject({ messageKey: 'errors.INVALID_CREDENTIALS', code: 'INVALID_CREDENTIALS', status: 401 });
  });

  it('keeps password policy violations and retry delays', () => {
    const policy = toApiProblem(
      new HttpErrorResponse({ status: 400, error: { code: 'PASSWORD_POLICY', violations: ['PASSWORD_TOO_SHORT', 3] } }),
    );
    expect(policy.violations).toEqual(['PASSWORD_TOO_SHORT']);
    const throttled = toApiProblem(
      new HttpErrorResponse({ status: 429, error: { code: 'TOO_MANY_ATTEMPTS', retryAfterSeconds: 60 } }),
    );
    expect(throttled.retryAfterSeconds).toBe(60);
  });

  it('falls back to generic and network messages', () => {
    expect(toApiProblem(new HttpErrorResponse({ status: 500, error: { code: 'INTERNAL_ERROR' } })).messageKey).toBe(
      'errors.GENERIC',
    );
    expect(toApiProblem(new HttpErrorResponse({ status: 0 })).messageKey).toBe('errors.NETWORK');
    expect(toApiProblem(new Error('boom')).messageKey).toBe('errors.GENERIC');
  });
});

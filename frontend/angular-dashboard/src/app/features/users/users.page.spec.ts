import { HttpTestingController } from '@angular/common/http/testing';
import { RoleDefinition, TenantUser } from '../../core/users/users.api';
import { nextRequest, settle } from '../../testing/http';
import { ADMIN, TECHNICIAN, setupPage } from '../../testing/page-setup';
import { UsersPage } from './users.page';

const ROLES: RoleDefinition[] = [
  { code: 'ORGANIZATION_ADMIN', description: '', assignableScopes: ['TENANT', 'ORGANIZATION'], permissions: [] },
  { code: 'TECHNICIAN', description: '', assignableScopes: ['TENANT', 'ORGANIZATION', 'CUSTOMER', 'HOME'], permissions: [] },
  { code: 'CUSTOMER', description: '', assignableScopes: ['TENANT', 'CUSTOMER', 'HOME'], permissions: [] },
  { code: 'READ_ONLY', description: '', assignableScopes: ['TENANT', 'ORGANIZATION', 'CUSTOMER', 'HOME'], permissions: [] },
];

function user(id: string, email: string, extra: Partial<TenantUser> = {}): TenantUser {
  return {
    id, email, displayName: email.split('@')[0], locale: 'it', status: 'ACTIVE', invitationPending: false,
    createdAt: '2026-11-16T09:00:00Z', lastLoginAt: null,
    roles: [{ id: 'ra-' + id, role: 'READ_ONLY', scopeType: 'TENANT', scopeId: null, grantedBy: null,
      grantedAt: '2026-11-16T09:00:00Z' }],
    ...extra,
  };
}

const USERS = [
  user('admin', 'admin@example.test', { roles: [{ id: 'ra-admin', role: 'ORGANIZATION_ADMIN', scopeType: 'TENANT',
    scopeId: null, grantedBy: null, grantedAt: '2026-11-16T09:00:00Z' }] }),
  user('u2', 'lettore@example.test'),
  user('u3', 'invitato@example.test', { status: 'PENDING_VERIFICATION', invitationPending: true }),
];

describe('UsersPage', () => {
  let http: HttpTestingController;

  async function asAdmin() {
    const setup = await setupPage(UsersPage, ADMIN);
    http = setup.http;
    http.expectOne('/api/v1/users').flush(USERS);
    (await nextRequest(http, '/api/v1/roles')).flush(ROLES);
    (await nextRequest(http, '/api/v1/homes')).flush([
      { id: 'h1', name: 'Casa Rossi', customerId: 'c1', address: null, timezone: 'Europe/Rome',
        createdAt: '2026-11-16T09:00:00Z', updatedAt: '2026-11-16T09:00:00Z' },
    ]);
    (await nextRequest(http, '/api/v1/customers')).flush([
      { id: 'c1', displayName: 'Rossi', contactEmail: null, contactPhone: null, notes: null,
        createdAt: '2026-11-16T09:00:00Z', updatedAt: '2026-11-16T09:00:00Z' },
    ]);
    await settle();
    setup.fixture.detectChanges();
    return setup.fixture;
  }

  const row = (page: HTMLElement, email: string) => page.querySelector<HTMLElement>(`[data-user="${email}"]`)!;
  const button = (root: HTMLElement, id: string) => root.querySelector<HTMLButtonElement>(`[data-testid="${id}"]`);

  afterEach(() => http.verify());

  it('lists users with their state and never offers to disable yourself', async () => {
    const fixture = await asAdmin();
    const page = fixture.nativeElement as HTMLElement;

    expect(row(page, 'invitato@example.test').textContent).toContain('Invito inviato');
    expect(button(row(page, 'invitato@example.test'), 'resend')).not.toBeNull();
    expect(button(row(page, 'admin@example.test'), 'disable')).toBeNull();
    expect(row(page, 'lettore@example.test').textContent).toContain('Tutta l\'organizzazione');
  });

  it('asks for confirmation before disabling a user', async () => {
    const fixture = await asAdmin();
    const page = fixture.nativeElement as HTMLElement;
    const reader = row(page, 'lettore@example.test');

    button(reader, 'disable')!.click();
    fixture.detectChanges();
    http.expectNone('/api/v1/users/u2');
    expect(reader.textContent).toContain('disconnesso subito');

    button(reader, 'confirm-disable')!.click();
    const request = await nextRequest(http, '/api/v1/users/u2');
    expect(request.request.method).toBe('PATCH');
    expect(request.request.body).toEqual({ status: 'DISABLED' });
    request.flush({ ...USERS[1], status: 'DISABLED' });
    (await nextRequest(http, '/api/v1/users')).flush([USERS[0], { ...USERS[1], status: 'DISABLED' }, USERS[2]]);
    await settle();
    fixture.detectChanges();

    expect(button(row(page, 'lettore@example.test'), 'enable')).not.toBeNull();
  });

  it('invites a user with a role limited to one home and explains plan limits', async () => {
    const fixture = await asAdmin();
    const page = fixture.nativeElement as HTMLElement;
    const component = fixture.componentInstance;

    component.inviteForm.patchValue({ email: 'nuovo@example.test', displayName: ' Nuovo ', role: 'TECHNICIAN' });
    component.inviteForm.controls.scopeType.setValue('HOME');
    expect(component.inviteForm.controls.scopeId.value).toBe('h1');
    // platform-wide scopes are never offered
    expect(component.scopesFor('ORGANIZATION_ADMIN')).toEqual(['TENANT']);

    const sending = component.invite();
    const request = await nextRequest(http, '/api/v1/users');
    expect(request.request.method).toBe('POST');
    expect(request.request.body).toEqual({
      email: 'nuovo@example.test', displayName: 'Nuovo', locale: 'it', role: 'TECHNICIAN', scopeType: 'HOME',
      scopeId: 'h1',
    });
    request.flush({ status: 409, code: 'PLAN_LIMIT_REACHED', resource: 'USERS' }, { status: 409, statusText: 'Conflict' });
    await sending;
    fixture.detectChanges();

    expect(page.querySelector('[data-testid="problem"]')?.textContent).toContain('limite del tuo piano');
  });

  it('removes a role only after confirmation', async () => {
    const fixture = await asAdmin();
    const reader = row(fixture.nativeElement as HTMLElement, 'lettore@example.test');

    button(reader, 'remove-role')!.click();
    fixture.detectChanges();
    http.expectNone('/api/v1/users/u2/roles/ra-u2');

    button(reader, 'confirm-remove-role')!.click();
    const request = await nextRequest(http, '/api/v1/users/u2/roles/ra-u2');
    expect(request.request.method).toBe('DELETE');
    request.flush(null);
    (await nextRequest(http, '/api/v1/users')).flush(USERS);
    await settle();
  });

  it('shows no management controls to users who cannot manage users', async () => {
    const setup = await setupPage(UsersPage, TECHNICIAN);
    http = setup.http;
    http.expectOne('/api/v1/users').flush({ status: 403, code: 'FORBIDDEN' }, { status: 403, statusText: 'Forbidden' });
    await settle();
    setup.fixture.detectChanges();
    const page = setup.fixture.nativeElement as HTMLElement;

    expect(page.querySelector('[role="alert"]')?.textContent).toContain('Non hai i permessi');
    expect(page.querySelector('#inviteEmail')).toBeNull();
  });
});

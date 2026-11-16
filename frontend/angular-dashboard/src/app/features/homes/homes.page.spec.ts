import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { signal } from '@angular/core';
import { provideRouter } from '@angular/router';
import { Me } from '../../core/auth/auth.models';
import { AuthService } from '../../core/auth/auth.service';
import { ME } from '../../testing/auth-fixtures';
import { nextRequest, settle } from '../../testing/http';
import { translocoTesting } from '../../testing/transloco-testing';
import { HomesPage } from './homes.page';

const READ_ONLY: Me = {
  ...ME,
  roles: [{ id: 'r2', role: 'READ_ONLY', scopeType: 'TENANT', scopeId: null }],
  permissions: ['home:read', 'agent:read'],
};

describe('HomesPage', () => {
  let http: HttpTestingController;

  async function setup(me: Me) {
    await TestBed.configureTestingModule({
      imports: [HomesPage, translocoTesting()],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideRouter([]),
        { provide: AuthService, useValue: { me: signal(me), hasPermission: (p: string) => me.permissions.includes(p) } },
      ],
    }).compileComponents();
    http = TestBed.inject(HttpTestingController);
    const fixture = TestBed.createComponent(HomesPage);
    fixture.detectChanges();
    return fixture;
  }

  async function render(fixture: Awaited<ReturnType<typeof setup>>) {
    await settle();
    fixture.detectChanges();
    await fixture.whenStable();
    return fixture.nativeElement as HTMLElement;
  }

  afterEach(() => http.verify());

  it('invites to create a home only when the user is allowed to', async () => {
    const fixture = await setup(ME);
    http.expectOne('/api/v1/homes').flush([]);
    const page = await render(fixture);

    expect(page.querySelector('[data-testid="no-homes"]')?.textContent).toContain('Creane una');
    expect(page.querySelector('#homeName')).not.toBeNull();
  });

  it('does not suggest creating homes to read-only users', async () => {
    const fixture = await setup(READ_ONLY);
    http.expectOne('/api/v1/homes').flush([]);
    const page = await render(fixture);

    expect(page.querySelector('[data-testid="no-homes"]')?.textContent).toContain('Nessuna abitazione disponibile');
    expect(page.querySelector('#homeName')).toBeNull();
  });

  it('shows only the error, not the empty state, when the list cannot be loaded', async () => {
    const fixture = await setup({ ...ME, roles: [], permissions: [] });
    http.expectOne('/api/v1/homes').flush(
      { status: 403, code: 'FORBIDDEN', title: 'Forbidden' },
      { status: 403, statusText: 'Forbidden' },
    );
    const page = await render(fixture);

    expect(page.querySelector('[role="alert"]')).not.toBeNull();
    expect(page.querySelector('[data-testid="no-homes"]')).toBeNull();
  });

  it('creates homes of their own customer for customer-scoped users', async () => {
    const customerUser: Me = {
      ...ME,
      tenant: { id: 't1', type: 'BUSINESS', name: 'Installatori Srl', organizationId: 'o1' },
      roles: [{ id: 'r3', role: 'CUSTOMER', scopeType: 'CUSTOMER', scopeId: 'c1' }],
      permissions: [...ME.permissions, 'customer:read', 'tenant:read'],
    };
    const fixture = await setup(customerUser);
    http.expectOne('/api/v1/homes').flush([]);
    (await nextRequest(http, '/api/v1/customers')).flush([
      { id: 'c1', displayName: 'Rossi', contactEmail: null, contactPhone: null, notes: null,
        createdAt: '2026-11-16T09:00:00Z', updatedAt: '2026-11-16T09:00:00Z' },
    ]);
    const page = await render(fixture);
    const component = fixture.componentInstance;

    // no "without customer" option: only tenant-wide users can create homes outside a customer
    const options = [...page.querySelectorAll<HTMLOptionElement>('#homeCustomer option')].map((o) => o.value);
    expect(options).toEqual(['c1']);
    expect(component.form.controls.customerId.value).toBe('c1');

    component.form.controls.name.setValue('Casa nuova');
    const creating = component.create();
    const request = await nextRequest(http, '/api/v1/homes');
    expect(request.request.method).toBe('POST');
    expect(request.request.body).toEqual({ name: 'Casa nuova', customerId: 'c1', address: null, timezone: null });
    request.flush({});
    (await nextRequest(http, '/api/v1/homes')).flush([]);
    (await nextRequest(http, '/api/v1/customers')).flush([]);
    await creating;
  });

  it('formats dates in Italian', async () => {
    const fixture = await setup(ME);
    http.expectOne('/api/v1/homes').flush([{ id: 'h1', name: 'Casa', customerId: null, createdAt: '2026-11-16T12:00:00Z' }]);
    const page = await render(fixture);

    expect(page.querySelector('table')?.textContent).toContain('16 nov 2026');
  });
});

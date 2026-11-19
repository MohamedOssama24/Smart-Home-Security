import { HttpTestingController } from '@angular/common/http/testing';
import { Me } from '../../core/auth/auth.models';
import { Organization, TenantOverview } from '../../core/tenancy/tenancy.api';
import { ME } from '../../testing/auth-fixtures';
import { nextRequest, settle } from '../../testing/http';
import { ADMIN, TECHNICIAN, setupPage } from '../../testing/page-setup';
import { OrganizationPage } from './organization.page';

const PLAN = { code: 'FREE', maxHomes: 2, maxUsers: 3, maxCustomers: 2, maxNetworksPerHome: 4, maxAgentsPerHome: 2, maxScansPerDay: 10 };
const BUSINESS: TenantOverview = {
  id: 't1', type: 'BUSINESS', name: 'Installatori Srl', status: 'ACTIVE', organizationId: 'o1', plan: PLAN,
  usage: { homes: 1, users: 2, customers: 0 },
};
const ORGANIZATION: Organization = {
  id: 'o1', legalName: 'Installatori Srl', vatNumber: null, contactEmail: null, contactPhone: null,
  createdAt: '2026-11-16T09:00:00Z', updatedAt: '2026-11-16T09:00:00Z',
};

describe('OrganizationPage', () => {
  let http: HttpTestingController;

  async function load(me: Me, tenant: TenantOverview) {
    const setup = await setupPage(OrganizationPage, me);
    http = setup.http;
    http.expectOne('/api/v1/tenants/current').flush(tenant);
    if (tenant.type === 'BUSINESS') {
      (await nextRequest(http, '/api/v1/organizations/current')).flush(ORGANIZATION);
    }
    await settle();
    setup.fixture.detectChanges();
    return setup.fixture;
  }

  afterEach(() => http.verify());

  it('shows the plan with the current usage', async () => {
    const fixture = await load(ADMIN, BUSINESS);
    const plan = (fixture.nativeElement as HTMLElement).querySelector('[data-testid="plan"]')!.textContent!;

    expect(plan).toMatch(/Abitazioni\s*1 \/\s*2/);
    expect(plan).toMatch(/Utenti\s*2 \/\s*3/);
    expect(plan).toMatch(/Clienti\s*0 \/\s*2/);
  });

  it('saves the organization details with a normalized body', async () => {
    const fixture = await load(ADMIN, BUSINESS);
    const component = fixture.componentInstance;

    component.form.setValue({ legalName: 'Installatori Srl ', vatNumber: 'IT 12345678901', contactEmail: '',
      contactPhone: '' });
    const saving = component.save();
    const request = await nextRequest(http, '/api/v1/organizations/current');
    expect(request.request.method).toBe('PUT');
    expect(request.request.body).toEqual({ legalName: 'Installatori Srl', vatNumber: 'IT 12345678901',
      contactEmail: null, contactPhone: null });
    request.flush({ ...ORGANIZATION, vatNumber: 'IT12345678901' });
    await saving;
    expect(component.form.controls.vatNumber.value).toBe('IT12345678901');
    expect(component.saved()).toBe(true);
  });

  it('is read-only without organization:manage', async () => {
    const fixture = await load(TECHNICIAN, { ...BUSINESS, usage: null });
    const page = fixture.nativeElement as HTMLElement;

    expect(page.querySelector<HTMLInputElement>('#legalName')!.readOnly).toBe(true);
    expect(page.querySelector('button[type="submit"]')).toBeNull();
    await fixture.componentInstance.save();
    http.expectNone('/api/v1/organizations/current');
  });

  it('individual tenants see the plan only', async () => {
    const fixture = await load({ ...ME, permissions: [...ME.permissions, 'tenant:read'] }, {
      ...BUSINESS, type: 'INDIVIDUAL', organizationId: null, name: 'Mario',
    });
    const page = fixture.nativeElement as HTMLElement;

    expect(page.querySelector('#legalName')).toBeNull();
    expect(page.querySelector('[data-testid="plan"]')!.textContent).not.toContain('Clienti');
  });
});

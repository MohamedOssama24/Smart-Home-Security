import { HttpTestingController } from '@angular/common/http/testing';
import { Customer } from '../../core/customers/customers.api';
import { nextRequest, settle } from '../../testing/http';
import { ADMIN, TECHNICIAN, setupPage } from '../../testing/page-setup';
import { CustomersPage } from './customers.page';

const CUSTOMER: Customer = {
  id: 'c1', displayName: 'Famiglia Rossi', contactEmail: 'rossi@example.test', contactPhone: null, notes: null,
  createdAt: '2026-11-16T09:00:00Z', updatedAt: '2026-11-16T09:00:00Z',
};

describe('CustomersPage', () => {
  let http: HttpTestingController;

  async function load(me = ADMIN, customers: Customer[] = [CUSTOMER]) {
    const setup = await setupPage(CustomersPage, me);
    http = setup.http;
    http.expectOne('/api/v1/customers').flush(customers);
    await settle();
    setup.fixture.detectChanges();
    return setup.fixture;
  }

  const button = (root: HTMLElement, id: string) => root.querySelector<HTMLButtonElement>(`[data-testid="${id}"]`);

  afterEach(() => http.verify());

  it('creates a customer clearing empty optional fields', async () => {
    const fixture = await load(ADMIN, []);
    const component = fixture.componentInstance;
    expect((fixture.nativeElement as HTMLElement).querySelector('[data-testid="no-customers"]')).not.toBeNull();

    component.form.setValue({ displayName: ' Bianchi ', contactEmail: '', contactPhone: '', notes: '' });
    const saving = component.save();
    const request = await nextRequest(http, '/api/v1/customers');
    expect(request.request.method).toBe('POST');
    expect(request.request.body).toEqual({ displayName: 'Bianchi', contactEmail: null, contactPhone: null, notes: null });
    request.flush({ ...CUSTOMER, id: 'c2', displayName: 'Bianchi' });
    (await nextRequest(http, '/api/v1/customers')).flush([{ ...CUSTOMER, id: 'c2', displayName: 'Bianchi' }]);
    await saving;
    expect(component.customers().length).toBe(1);
  });

  it('archives only after confirmation and explains why it can be refused', async () => {
    const fixture = await load();
    const page = fixture.nativeElement as HTMLElement;

    button(page, 'archive')!.click();
    fixture.detectChanges();
    http.expectNone('/api/v1/customers/c1');

    button(page, 'confirm-archive')!.click();
    const request = await nextRequest(http, '/api/v1/customers/c1');
    expect(request.request.method).toBe('DELETE');
    request.flush({ status: 409, code: 'CUSTOMER_HAS_HOMES' }, { status: 409, statusText: 'Conflict' });
    await settle();
    fixture.detectChanges();

    expect(page.querySelector('[role="alert"]')?.textContent).toContain('ha ancora delle abitazioni');
  });

  it('edits with a full replacement of the fields', async () => {
    const fixture = await load();
    const component = fixture.componentInstance;

    component.edit(CUSTOMER);
    component.form.controls.contactEmail.setValue('');
    const saving = component.save();
    const request = await nextRequest(http, '/api/v1/customers/c1');
    expect(request.request.method).toBe('PUT');
    expect(request.request.body).toEqual({ displayName: 'Famiglia Rossi', contactEmail: null, contactPhone: null, notes: null });
    request.flush({ ...CUSTOMER, contactEmail: null });
    (await nextRequest(http, '/api/v1/customers')).flush([{ ...CUSTOMER, contactEmail: null }]);
    await saving;
    expect(component.editing()).toBeNull();
  });

  it('is read-only for technicians', async () => {
    const fixture = await load(TECHNICIAN);
    const page = fixture.nativeElement as HTMLElement;

    expect(page.textContent).toContain('Famiglia Rossi');
    expect(button(page, 'archive')).toBeNull();
    expect(page.querySelector('#customerName')).toBeNull();
  });
});

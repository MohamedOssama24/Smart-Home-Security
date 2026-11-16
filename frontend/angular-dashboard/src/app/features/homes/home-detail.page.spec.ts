import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { signal } from '@angular/core';
import { provideRouter } from '@angular/router';
import { AuthService } from '../../core/auth/auth.service';
import { Me } from '../../core/auth/auth.models';
import { Agent, Home, Network } from '../../core/homes/homes.api';
import { ME } from '../../testing/auth-fixtures';
import { nextRequest, settle } from '../../testing/http';
import { translocoTesting } from '../../testing/transloco-testing';
import { HomeDetailPage } from './home-detail.page';

const AGENT: Agent = {
  id: 'a1', homeId: 'h1', name: 'PC salotto', hostname: 'pc-salotto', os: 'windows', arch: 'amd64',
  agentVersion: '1.0.0', status: 'ACTIVE', enrolledAt: '2026-11-16T09:00:00Z', lastSeenAt: '2026-11-16T10:00:00Z',
  revokedAt: null, revokeReason: null,
};

const HOME: Home = {
  id: 'h1', name: 'Casa', customerId: null, address: null, timezone: 'Europe/Rome',
  createdAt: '2026-11-16T09:00:00Z', updatedAt: '2026-11-16T09:00:00Z',
};

const NETWORK: Network = {
  id: 'n1', homeId: 'h1', name: 'Wi-Fi', cidr: '192.168.1.0/24', ipVersion: 4, kind: 'WIFI', source: 'MANUAL',
  authorized: false, authorization: null, createdAt: '2026-11-16T09:00:00Z', updatedAt: '2026-11-16T09:00:00Z',
};

const MANAGER: Me = {
  ...ME,
  permissions: [...ME.permissions, 'network:manage', 'network:authorize'],
};

describe('HomeDetailPage', () => {
  let http: HttpTestingController;

  async function setup(networks: Network[] = [], me: Me = ME) {
    await TestBed.configureTestingModule({
      imports: [HomeDetailPage, translocoTesting()],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideRouter([]),
        { provide: AuthService, useValue: { me: signal(me), hasPermission: (p: string) => me.permissions.includes(p) } },
      ],
    }).compileComponents();
    http = TestBed.inject(HttpTestingController);
    const fixture = TestBed.createComponent(HomeDetailPage);
    fixture.componentRef.setInput('id', 'h1');
    fixture.detectChanges();
    http.expectOne('/api/v1/homes/h1').flush(HOME);
    (await nextRequest(http, '/api/v1/homes/h1/agents')).flush([AGENT]);
    if (me.permissions.includes('agent:enroll')) {
      (await nextRequest(http, '/api/v1/homes/h1/agent-enrollment-tokens')).flush([]);
    }
    (await nextRequest(http, '/api/v1/homes/h1/networks')).flush(networks);
    await settle();
    fixture.detectChanges();
    await fixture.whenStable();
    return fixture;
  }

  const button = (root: HTMLElement, id: string) => root.querySelector<HTMLButtonElement>(`[data-testid="${id}"]`);

  afterEach(() => http.verify());

  it('asks for confirmation before revoking an agent', async () => {
    const fixture = await setup();
    const page = fixture.nativeElement as HTMLElement;

    button(page, 'revoke')!.click();
    fixture.detectChanges();

    // first click: nothing is sent, the irreversible action needs a second click
    http.expectNone('/api/v1/agents/a1/revoke');
    expect(page.textContent).toContain('dovrà essere registrato di nuovo');

    button(page, 'confirm-revoke')!.click();
    (await nextRequest(http, '/api/v1/agents/a1/revoke')).flush({ ...AGENT, status: 'REVOKED' });
    (await nextRequest(http, '/api/v1/homes/h1/agents')).flush([{ ...AGENT, status: 'REVOKED' }]);
    await settle();
    fixture.detectChanges();

    expect(fixture.componentInstance.confirmingRevoke()).toBeNull();
    expect(button(page, 'revoke')).toBeNull();
  });

  it('authorizes a network only after the explicit, unticked-by-default attestation', async () => {
    const fixture = await setup([NETWORK], MANAGER);
    const page = fixture.nativeElement as HTMLElement;

    button(page, 'authorize')!.click();
    fixture.detectChanges();
    const checkbox = page.querySelector<HTMLInputElement>('[data-testid="attestation-checkbox"]')!;
    expect(checkbox.checked).toBe(false);
    expect(page.querySelector('[data-testid="attestation"]')?.textContent).toContain('192.168.1.0/24');
    // without the tick nothing can be sent
    expect(button(page, 'confirm-authorize')!.disabled).toBe(true);
    await fixture.componentInstance.authorize(NETWORK);
    http.expectNone('/api/v1/networks/n1/authorization');

    checkbox.click();
    fixture.detectChanges();
    button(page, 'confirm-authorize')!.click();
    const request = await nextRequest(http, '/api/v1/networks/n1/authorization');
    expect(request.request.method).toBe('POST');
    expect(request.request.body).toEqual({ attestation: true, attestationVersion: '1' });
    const authorized = { ...NETWORK, authorized: true,
      authorization: { authorizedBy: 'u1', authorizedAt: '2026-11-16T10:00:00Z', attestationVersion: '1' } };
    request.flush(authorized);
    (await nextRequest(http, '/api/v1/homes/h1/networks')).flush([authorized]);
    await settle();
    fixture.detectChanges();

    expect(page.querySelector('[data-testid="attestation"]')).toBeNull();
    expect(button(page, 'revoke-authorization')).not.toBeNull();
  });

  it('declares a network and shows the reason when the backend refuses it', async () => {
    const fixture = await setup([], MANAGER);
    const page = fixture.nativeElement as HTMLElement;
    const component = fixture.componentInstance;

    component.networkForm.setValue({ name: 'Pubblica', cidr: ' 8.8.8.0/24 ', kind: 'WIFI' });
    const saving = component.addNetwork();
    const request = await nextRequest(http, '/api/v1/homes/h1/networks');
    expect(request.request.method).toBe('POST');
    expect(request.request.body).toEqual({ name: 'Pubblica', cidr: '8.8.8.0/24', kind: 'WIFI' });
    request.flush({ status: 400, code: 'NETWORK_NOT_PRIVATE' }, { status: 400, statusText: 'Bad Request' });
    await saving;
    fixture.detectChanges();

    expect(page.querySelector('[role="alert"]')?.textContent).toContain('Sono ammesse solo reti private');
  });

  it('hides network and home actions from users without the permissions', async () => {
    const reader: Me = { ...ME, permissions: ['home:read', 'agent:read'] };
    const fixture = await setup([NETWORK], reader);
    const page = fixture.nativeElement as HTMLElement;

    expect(page.querySelector('[data-network="192.168.1.0/24"]')).not.toBeNull();
    expect(button(page, 'authorize')).toBeNull();
    expect(button(page, 'delete-network')).toBeNull();
    expect(button(page, 'edit-home')).toBeNull();
    expect(page.querySelector('#networkCidr')).toBeNull();
  });

  it('asks for confirmation before archiving the home', async () => {
    const fixture = await setup([], MANAGER);
    const page = fixture.nativeElement as HTMLElement;

    button(page, 'archive-home')!.click();
    fixture.detectChanges();
    http.expectNone('/api/v1/homes/h1');

    button(page, 'confirm-archive-home')!.click();
    const request = await nextRequest(http, '/api/v1/homes/h1');
    expect(request.request.method).toBe('DELETE');
    request.flush({ status: 409, code: 'HOME_HAS_ACTIVE_AGENTS' }, { status: 409, statusText: 'Conflict' });
    await settle();
    fixture.detectChanges();
    expect(page.querySelector('[role="alert"]')?.textContent).toContain('agent attivi');
  });

  it('sends every editable field when the home is updated', async () => {
    const fixture = await setup([], MANAGER);
    const component = fixture.componentInstance;

    component.startEdit(HOME);
    component.homeForm.setValue({ name: 'Casa nuova', address: '', timezone: 'Europe/London' });
    const saving = component.saveHome(HOME);
    const request = await nextRequest(http, '/api/v1/homes/h1');
    expect(request.request.method).toBe('PUT');
    expect(request.request.body).toEqual({ name: 'Casa nuova', customerId: null, address: null, timezone: 'Europe/London' });
    request.flush({ ...HOME, name: 'Casa nuova', timezone: 'Europe/London' });
    await saving;
    expect(component.home()?.name).toBe('Casa nuova');
    expect(component.editing()).toBe(false);
  });

  it('can cancel the revocation', async () => {
    const fixture = await setup();
    const page = fixture.nativeElement as HTMLElement;

    button(page, 'revoke')!.click();
    fixture.detectChanges();
    [...page.querySelectorAll('button')].find((b) => b.textContent?.trim() === 'Annulla')!.click();
    fixture.detectChanges();

    http.expectNone('/api/v1/agents/a1/revoke');
    expect(button(page, 'revoke')).not.toBeNull();
  });
});

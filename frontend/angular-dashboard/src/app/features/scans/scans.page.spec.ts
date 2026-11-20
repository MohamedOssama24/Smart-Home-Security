import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { signal } from '@angular/core';
import { provideRouter } from '@angular/router';
import { AuthService } from '../../core/auth/auth.service';
import { Scan } from '../../core/scans/scans.api';
import { ME } from '../../testing/auth-fixtures';
import { nextRequest, settle } from '../../testing/http';
import { translocoTesting } from '../../testing/transloco-testing';
import { ScansPage } from './scans.page';

const SCAN: Scan = {
  id: 's1', homeId: 'h1', agentId: 'a1', trigger: 'MANUAL', profile: 'DISCOVERY', status: 'QUEUED',
  requestedBy: 'u1', requestedAt: '2026-11-17T10:00:00Z', queuedAt: '2026-11-17T10:00:00Z', startedAt: null,
  completedAt: null, cancelRequestedAt: null, progress: null, devicesDiscovered: 0, outOfScopeDropped: 0,
  warnings: [], failureReason: null, targets: null, events: null,
};

describe('ScansPage', () => {
  let http: HttpTestingController;

  async function setup(history: Scan[], permissions = [...ME.permissions, 'scan:read', 'scan:create']) {
    await TestBed.configureTestingModule({
      imports: [ScansPage, translocoTesting()],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideRouter([]),
        { provide: AuthService, useValue: { hasPermission: (p: string) => permissions.includes(p), me: signal(ME) } },
      ],
    }).compileComponents();
    http = TestBed.inject(HttpTestingController);
    const fixture = TestBed.createComponent(ScansPage);
    fixture.componentRef.setInput('id', 'h1');
    fixture.detectChanges();
    (await nextRequest(http, '/api/v1/homes/h1/scans')).flush(history);
    await settle();
    fixture.detectChanges();
    return fixture;
  }

  const el = (root: HTMLElement, id: string) => root.querySelector<HTMLElement>(`[data-testid="${id}"]`);

  afterEach(() => {
    TestBed.resetTestingModule(); // stops the polling timer
    http.verify();
  });

  it('starts a scan with an idempotency key and follows it until the results', async () => {
    const fixture = await setup([]);
    const page = fixture.nativeElement as HTMLElement;

    el(page, 'start-scan')!.click();
    const create = await nextRequest(http, '/api/v1/homes/h1/scans');
    expect(create.request.method).toBe('POST');
    expect(create.request.headers.get('Idempotency-Key')).toMatch(/^[A-Za-z0-9-]{8,64}$/);
    expect(create.request.body).toEqual({ profile: 'DISCOVERY' });
    create.flush(SCAN);
    (await nextRequest(http, '/api/v1/homes/h1/scans')).flush([{ ...SCAN, status: 'RUNNING', devicesDiscovered: 2 }]);
    await settle();
    fixture.detectChanges();
    expect(el(page, 'active-scan')!.textContent).toContain('In corso');
    expect(el(page, 'start-scan')).toBeNull(); // one scan at a time

    // next poll: the scan has ended, its devices are shown
    const done = { ...SCAN, status: 'COMPLETED' as const, devicesDiscovered: 2 };
    const poll = fixture.componentInstance.refresh();
    (await nextRequest(http, '/api/v1/homes/h1/scans')).flush([done]);
    (await nextRequest(http, '/api/v1/scans/s1')).flush(done);
    (await nextRequest(http, '/api/v1/scans/s1/devices')).flush([
      { ip: '192.168.50.1', mac: 'aa:bb:cc:00:00:01', methods: ['ARP'], iface: 'eth0', observedAt: '2026-11-17T10:01:00Z' },
    ]);
    (await nextRequest(http, '/api/v1/scans/s1/integrations')).flush({ homeAssistant: null });
    await poll;
    fixture.detectChanges();
    expect(el(page, 'devices')!.textContent).toContain('192.168.50.1');
    expect(el(page, 'scan-detail')!.textContent).toContain('non indica vulnerabilità');
  });

  it('starts a port scan with the chosen profile and shows the open ports found', async () => {
    const fixture = await setup([]);
    const page = fixture.nativeElement as HTMLElement;
    const select = el(page, 'scan-profile') as HTMLSelectElement;
    expect([...select.options].map((o) => o.value)).toEqual(['DISCOVERY', 'QUICK', 'STANDARD']);
    select.value = 'QUICK';
    select.dispatchEvent(new Event('change'));
    fixture.detectChanges();
    expect(el(page, 'profile-hint')!.textContent).toContain('nessuna password');

    el(page, 'start-scan')!.click();
    const create = await nextRequest(http, '/api/v1/homes/h1/scans');
    expect(create.request.body).toEqual({ profile: 'QUICK' });
    const quick = { ...SCAN, profile: 'QUICK', status: 'RUNNING' as const, progress: { phase: 'PORTS', percent: 50 } };
    create.flush(quick);
    (await nextRequest(http, '/api/v1/homes/h1/scans')).flush([quick]);
    await settle();
    fixture.detectChanges();
    expect(el(page, 'scan-phase')!.textContent).toContain('controllo porte e servizi');

    const done = { ...quick, status: 'COMPLETED' as const, progress: null };
    const poll = fixture.componentInstance.refresh();
    (await nextRequest(http, '/api/v1/homes/h1/scans')).flush([done]);
    (await nextRequest(http, '/api/v1/scans/s1')).flush(done);
    (await nextRequest(http, '/api/v1/scans/s1/devices')).flush([]);
    (await nextRequest(http, '/api/v1/scans/s1/ports')).flush([
      { deviceId: null, ip: '192.168.50.20', protocol: 'TCP', port: 554, state: 'OPEN', reason: 'syn-ack',
        observedAt: '2026-11-17T10:02:00Z', service: { name: 'rtsp', product: 'MOCK-Camera', version: '2.1',
          status: 'CONFIRMED', confidence: 'HIGH', evidence: { authRequired: true }, tls: null } },
    ]);
    // [MOCK] Home Assistant inventory read by the agent
    (await nextRequest(http, '/api/v1/scans/s1/integrations')).flush({ homeAssistant: {
      ip: '192.168.50.5', version: '2026.11.2', https: false, deviceCount: 2, truncated: false,
      observedAt: '2026-11-17T10:02:00Z', protocols: { IP: 1, ZIGBEE: 1 }, devices: [
        { name: 'MOCK Sensore porta', manufacturer: 'Aqara', model: 'MCCGQ11LM', swVersion: null, protocol: 'ZIGBEE',
          macs: [], entities: 3, matchedIp: null },
        { name: 'MOCK Presa', manufacturer: 'Shelly', model: 'Plug S', swVersion: '1.14.0', protocol: 'IP',
          macs: ['aa:bb:cc:00:00:20'], entities: 5, matchedIp: '192.168.50.20' },
      ] } });
    await poll;
    fixture.detectChanges();
    const ports = el(page, 'ports')!.textContent!;
    expect(ports).toContain('192.168.50.20');
    expect(ports).toContain('554/tcp');
    expect(ports).toContain('MOCK-Camera 2.1');
    expect(ports).toContain('Richiede autenticazione');
    const ha = el(page, 'home-assistant')!.textContent!;
    expect(ha).toContain('192.168.50.5');
    expect(ha).toContain('Zigbee 1');
    expect(ha).toContain('MOCK Sensore porta');
    expect(ha).toContain('Shelly · Plug S · 1.14.0');
    expect(ha).toContain('192.168.50.20');
    expect(ha).toContain('HTTP non cifrato');
  });

  it('shows names, grouped addresses and what devices declare, marked as not verified', async () => {
    const fixture = await setup([{ ...SCAN, status: 'COMPLETED' }]);
    const page = fixture.nativeElement as HTMLElement;
    const select = fixture.componentInstance.select({ ...SCAN, status: 'COMPLETED' });
    (await nextRequest(http, '/api/v1/scans/s1')).flush({ ...SCAN, status: 'COMPLETED' });
    // [MOCK] devices
    (await nextRequest(http, '/api/v1/scans/s1/devices')).flush([
      { ip: '192.168.50.1', mac: null, methods: ['SSDP', 'UPNP_IGD'], iface: 'eth0', observedAt: '2026-11-17T10:01:00Z',
        addresses: ['192.168.50.1'], hostname: null, hostnames: [], evidence: [
          { method: 'SSDP', ip: '192.168.50.1', observedAt: '2026-11-17T10:01:00Z',
            details: { selfDeclared: true, friendlyName: 'MOCK Router', modelName: 'R-1' } },
          { method: 'UPNP_IGD', ip: '192.168.50.1', observedAt: '2026-11-17T10:01:00Z', details: { selfDeclared: true,
            portMappings: [{ protocol: 'TCP', externalPort: 8080, internalClient: '192.168.50.20', internalPort: 80, enabled: true }] } },
        ] },
      { ip: '192.168.50.20', mac: 'aa:bb:cc:00:00:20', methods: ['ARP', 'MDNS', 'NDP'], iface: 'eth0',
        observedAt: '2026-11-17T10:01:00Z', addresses: ['192.168.50.20', 'fd00::20'], hostname: 'mock-nas',
        hostnames: [{ name: 'mock-nas', method: 'MDNS' }], evidence: [
          { method: 'MDNS', ip: '192.168.50.20', observedAt: '2026-11-17T10:01:00Z',
            details: { selfDeclared: true, services: [{ type: '_smb._tcp', port: 445 }] } },
        ] },
    ]);
    (await nextRequest(http, '/api/v1/scans/s1/integrations')).flush({ homeAssistant: null });
    await select;
    fixture.detectChanges();
    const table = el(page, 'devices')!.textContent!;
    expect(table).toContain('mock-nas');
    expect(table).toContain('fd00::20');
    expect(table).toContain('_smb._tcp:445');
    expect(table).toContain('MOCK Router · R-1');
    expect(table).toContain('Dichiarato dal dispositivo, non verificato.');
    expect(el(page, 'port-mappings')!.textContent).toContain('TCP 8080 → 192.168.50.20:80');
  });

  it('cancels the active scan', async () => {
    const fixture = await setup([{ ...SCAN, status: 'RUNNING' }]);
    el(fixture.nativeElement, 'cancel-scan')!.click();
    const cancel = await nextRequest(http, '/api/v1/scans/s1/cancel');
    expect(cancel.request.method).toBe('POST');
    cancel.flush({ ...SCAN, status: 'RUNNING', cancelRequestedAt: '2026-11-17T10:02:00Z' });
    const cancelled = { ...SCAN, status: 'CANCELLED' as const, failureReason: 'USER_CANCELLED' };
    (await nextRequest(http, '/api/v1/homes/h1/scans')).flush([cancelled]);
    (await nextRequest(http, '/api/v1/scans/s1')).flush(cancelled);
    (await nextRequest(http, '/api/v1/scans/s1/devices')).flush([]);
    (await nextRequest(http, '/api/v1/scans/s1/integrations')).flush({ homeAssistant: null });
    await settle();
    fixture.detectChanges();
    expect(el(fixture.nativeElement, 'active-scan')).toBeNull();
    expect(el(fixture.nativeElement, 'scan-detail')!.textContent).toContain("Annullata dall'utente");
  });

  it('explains why a scan cannot start and keeps the key for the retry', async () => {
    const fixture = await setup([]);
    const page = fixture.nativeElement as HTMLElement;
    el(page, 'start-scan')!.click();
    const first = await nextRequest(http, '/api/v1/homes/h1/scans');
    first.flush({ code: 'AGENT_OFFLINE' }, { status: 409, statusText: 'Conflict' });
    await settle();
    fixture.detectChanges();
    expect(page.textContent).toContain('Nessun agent online');

    el(page, 'start-scan')!.click();
    const retry = await nextRequest(http, '/api/v1/homes/h1/scans');
    expect(retry.request.headers.get('Idempotency-Key')).toBe(first.request.headers.get('Idempotency-Key'));
    retry.flush({ code: 'AGENT_OFFLINE' }, { status: 409, statusText: 'Conflict' });
  });

  it('hides the actions from read-only users', async () => {
    const fixture = await setup([{ ...SCAN, status: 'RUNNING' }], [...ME.permissions, 'scan:read']);
    expect(el(fixture.nativeElement, 'start-scan')).toBeNull();
    expect(el(fixture.nativeElement, 'cancel-scan')).toBeNull();
    expect(el(fixture.nativeElement, 'clear-home')).toBeNull();
  });

  it('deletes a finished scan and clears the inventory only after a second confirmation', async () => {
    const done = { ...SCAN, status: 'COMPLETED' as const, completedAt: '2026-11-17T10:05:00Z' };
    const running = { ...SCAN, id: 's2', status: 'RUNNING' as const };
    const fixture = await setup([running, done], [...ME.permissions, 'scan:read', 'scan:create', 'scan:delete']);
    const page = fixture.nativeElement as HTMLElement;
    expect(el(page, 'delete-s2')).toBeNull(); // a running scan cannot be deleted
    expect(el(page, 'clear-home')).toBeNull(); // nor the inventory while a scan runs
    el(page, 'cancel-scan')!.click();
    (await nextRequest(http, '/api/v1/scans/s2/cancel')).flush({ ...running, cancelRequestedAt: '2026-11-17T10:06:00Z' });
    const cancelled = { ...running, status: 'CANCELLED' as const };
    (await nextRequest(http, '/api/v1/homes/h1/scans')).flush([cancelled, done]);
    (await nextRequest(http, '/api/v1/scans/s2')).flush(cancelled);
    (await nextRequest(http, '/api/v1/scans/s2/devices')).flush([]);
    (await nextRequest(http, '/api/v1/scans/s2/integrations')).flush({ homeAssistant: null });
    await settle();
    fixture.detectChanges();

    el(page, 'delete-s1')!.click();
    fixture.detectChanges();
    expect(page.textContent).toContain('Eliminazione definitiva');
    el(page, 'delete-confirm-s1')!.click();
    const del = await nextRequest(http, '/api/v1/scans/s1');
    expect(del.request.method).toBe('DELETE');
    del.flush({ scans: 1, devices: 2, findings: 0 });
    (await nextRequest(http, '/api/v1/homes/h1/scans')).flush([cancelled]);
    await settle();
    fixture.detectChanges();
    expect(el(page, 'deleted-info')!.textContent).toContain('2 dispositivi');

    el(page, 'clear-home')!.click();
    fixture.detectChanges();
    el(page, 'clear-confirm')!.click();
    const clear = await nextRequest(http, '/api/v1/homes/h1/inventory');
    expect(clear.request.method).toBe('DELETE');
    clear.flush({ scans: 1, devices: 0, findings: 0 });
    (await nextRequest(http, '/api/v1/homes/h1/scans')).flush([]);
    await settle();
    fixture.detectChanges();
    expect(el(page, 'scan-detail')).toBeNull();
    expect(el(page, 'deleted-info')!.textContent).toContain('1 scansioni, 0 dispositivi');
    expect(el(page, 'history')).toBeNull();
  });
});

import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { signal } from '@angular/core';
import { provideRouter } from '@angular/router';
import { AuthService } from '../../core/auth/auth.service';
import { Device } from '../../core/devices/devices.api';
import { Person } from '../../core/people/people.api';
import { ME } from '../../testing/auth-fixtures';
import { nextRequest, settle } from '../../testing/http';
import { translocoTesting } from '../../testing/transloco-testing';
import { DevicesPage } from './devices.page';

// [MOCK] devices
const PRINTER: Device = {
  id: 'd1', homeId: 'h1', mac: '00:11:22:00:60:10', macRandomized: false, probableSameAs: null, ip: '192.168.60.10',
  addresses: ['192.168.60.10'], hostname: 'mock-printer', manufacturer: 'MOCK Printers', model: null, os: null,
  category: 'PRINTER', detectedCategory: 'PRINTER', detectedCategoryConfidence: 'HIGH', manualCategory: null,
  manualCategoryAt: null, suggestedCategory: null, overallConfidence: 'MEDIUM', rulesetVersion: '2026.11-1',
  classification: { matches: [
    { rule: 'printer.mdns-ipp', category: 'PRINTER', strength: 'STRONG', sources: ['MDNS'], values: ['_ipp._tcp'] },
  ] },
  firstSeenAt: '2026-11-17T10:00:00Z', lastSeenAt: '2026-11-17T10:00:00Z', lastScanId: 's1',
  identifications: null, categoryHistory: null,
};
const PHONE: Device = {
  ...PRINTER, id: 'd2', mac: 'da:a1:19:00:60:30', macRandomized: true, probableSameAs: 'd3', hostname: null,
  manufacturer: null, category: 'UNKNOWN_DEVICE', detectedCategory: 'UNKNOWN_DEVICE', detectedCategoryConfidence: null,
  overallConfidence: 'LOW', classification: { matches: [] },
};
const OLD_PHONE: Device = { ...PHONE, id: 'd3', mac: 'da:a1:19:00:60:31', probableSameAs: null, hostname: 'Mock-Phone',
  lastSeenAt: '2026-11-16T10:00:00Z', lastScanId: 's0' };

describe('DevicesPage', () => {
  let http: HttpTestingController;

  async function setup(permissions = [...ME.permissions, 'device:read', 'device:classify'], people: Person[] = []) {
    await TestBed.configureTestingModule({
      imports: [DevicesPage, translocoTesting()],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideRouter([]),
        { provide: AuthService, useValue: { hasPermission: (p: string) => permissions.includes(p), me: signal(ME) } },
      ],
    }).compileComponents();
    http = TestBed.inject(HttpTestingController);
    const fixture = TestBed.createComponent(DevicesPage);
    fixture.componentRef.setInput('id', 'h1');
    fixture.detectChanges();
    (await nextRequest(http, '/api/v1/homes/h1/devices')).flush([PRINTER, PHONE, OLD_PHONE]);
    (await nextRequest(http, '/api/v1/homes/h1/device-images')).flush([]);
    if (permissions.includes('person:read')) {
      (await nextRequest(http, '/api/v1/homes/h1/people')).flush(people);
    }
    await settle();
    fixture.detectChanges();
    return fixture;
  }

  const el = (root: HTMLElement, id: string) => root.querySelector<HTMLElement>(`[data-testid="${id}"]`);

  async function open(fixture: Awaited<ReturnType<typeof setup>>, device: Device, detail: Device) {
    const opening = fixture.componentInstance.open(device);
    (await nextRequest(http, `/api/v1/devices/${device.id}`)).flush(detail);
    (await nextRequest(http, `/api/v1/devices/${device.id}/images`)).flush([]);
    await opening;
    fixture.detectChanges();
  }

  afterEach(() => http.verify());

  it('uploads a photo, shows it first and lets the user remove it; refuses other formats', async () => {
    URL.createObjectURL = vi.fn(() => 'blob:mock-d1');
    URL.revokeObjectURL = vi.fn();
    const fixture = await setup();
    await open(fixture, PRINTER, PRINTER);
    expect(el(fixture.nativeElement, 'no-photo')).not.toBeNull();

    const svg = { files: [new File(['<svg/>'], 'x.svg', { type: 'image/svg+xml' })], value: 'x' } as unknown as HTMLInputElement;
    await fixture.componentInstance.uploadPhoto(PRINTER, svg);
    expect(fixture.componentInstance.problem()!.messageKey).toBe('devices.photo.invalid');

    // [MOCK] photo
    const user = { deviceId: 'd1', source: 'USER', origin: 'UPLOAD', contentType: 'image/jpeg', width: 640, height: 480,
      updatedAt: '2026-11-19T10:00:00Z', shown: true };
    const file = new File(['MOCK'], 'p.jpg', { type: 'image/jpeg' });
    const uploading = fixture.componentInstance.uploadPhoto(PRINTER, { files: [file], value: 'p.jpg' } as unknown as HTMLInputElement);
    const put = await nextRequest(http, '/api/v1/devices/d1/image');
    expect(put.request.method).toBe('PUT');
    expect(put.request.headers.get('Content-Type')).toBe('image/jpeg');
    put.flush([user]);
    (await nextRequest(http, '/api/v1/homes/h1/device-images')).flush([user]);
    (await nextRequest(http, '/api/v1/devices/d1/image')).flush(new Blob(['MOCK'], { type: 'image/jpeg' }));
    await uploading;
    fixture.detectChanges();
    expect(el(fixture.nativeElement, 'thumb-d1')!.getAttribute('src')).toBe('blob:mock-d1');
    expect(el(fixture.nativeElement, 'photo-source')!.textContent).toContain('Foto caricata da te');

    const removing = fixture.componentInstance.removePhoto(PRINTER);
    const del = await nextRequest(http, '/api/v1/devices/d1/image');
    expect(del.request.method).toBe('DELETE');
    del.flush([]);
    (await nextRequest(http, '/api/v1/homes/h1/device-images')).flush([]);
    await removing;
    fixture.detectChanges();
    expect(el(fixture.nativeElement, 'thumb-d1')).toBeNull();
    expect(el(fixture.nativeElement, 'no-photo')).not.toBeNull();
  });

  it('lists the inventory with category, confidence and randomized MACs', async () => {
    const fixture = await setup();
    const table = el(fixture.nativeElement, 'inventory')!.textContent!;
    expect(table).toContain('mock-printer');
    expect(table).toContain('Stampante');
    expect(table).toContain('alta');
    expect(table).toContain('Non identificato');
    expect(table).toContain('MAC casuale');
    // only the device not found by the last scan is marked
    expect(el(fixture.nativeElement, 'stale-d3')!.textContent).toContain("non visto nell'ultima scansione");
    expect(el(fixture.nativeElement, 'stale-d1')).toBeNull();
    expect(el(fixture.nativeElement, 'stale-d2')).toBeNull();
  });

  it('shows what was identified, from which sources, why, and the history', async () => {
    const fixture = await setup();
    await open(fixture, PRINTER, {
      ...PRINTER,
      identifications: [
        { field: 'MANUFACTURER', value: 'MOCK Printers', confidence: 'LOW', conflict: true, scanId: 's1',
          identifiedAt: '2026-11-17T10:00:00Z', sources: [
            { source: 'SSDP', value: 'MOCK Printers', reliability: 'M', agrees: true },
            { source: 'MDNS', value: 'MOCK Other', reliability: 'M', agrees: false },
          ] },
      ],
      categoryHistory: [{ source: 'AUTO', oldCategory: null, newCategory: 'PRINTER', scanId: 's1', changedBy: null,
        changedAt: '2026-11-17T10:00:00Z' }],
    });
    const page = fixture.nativeElement as HTMLElement;
    const ids = el(page, 'identifications')!.textContent!;
    expect(ids).toContain('Produttore');
    expect(ids).toContain('fonti in disaccordo');
    expect(ids).toContain('MDNS: MOCK Other (in disaccordo)');
    expect(el(page, 'matches')!.textContent).toContain('printer.mdns-ipp');
    expect(el(page, 'category-history')!.textContent).toContain('Automatica → Stampante');
  });

  it('shows the open ports of the last port scan, probable and confirmed services apart', async () => {
    const fixture = await setup();
    const port = { deviceId: 'd1', ip: '192.168.60.10', state: 'OPEN', reason: 'syn-ack', observedAt: '2026-11-17T10:02:00Z' };
    await open(fixture, PRINTER, {
      ...PRINTER,
      services: {
        scanId: 's2', scannedAt: '2026-11-17T10:02:00Z',
        summary: { profile: 'QUICK', tcp: { probed: 40, open: 2, closed: 37, filtered: 1, openFiltered: 0, unknown: 0 },
          udp: { probed: 6, open: 0, closed: 0, filtered: 0, openFiltered: 6, unknown: 0 }, paused: false },
        ports: [
          { ...port, protocol: 'TCP', port: 443, service: { name: 'https', product: 'MOCK-Web', version: '1.0',
            status: 'CONFIRMED', confidence: 'HIGH', evidence: { title: 'MOCK Printer', loginForm: true },
            tls: { versions: ['TLS1.2', 'TLS1.0'], expired: true, selfSigned: true } } },
          { ...port, protocol: 'TCP', port: 9100, service: { name: 'jetdirect', product: null, version: null,
            status: 'PROBABLE', confidence: 'LOW', evidence: {}, tls: null } },
        ],
        protocols: [{ protocol: 'HTTPS', confidence: 'HIGH', details: {} }, { protocol: 'JETDIRECT', confidence: 'LOW', details: {} }],
      },
    });
    const page = fixture.nativeElement as HTMLElement;
    const ports = el(page, 'ports')!.textContent!;
    expect(ports).toContain('443/tcp');
    expect(ports).toContain('confermato');
    expect(ports).toContain('9100/tcp');
    expect(ports).toContain('probabile');
    expect(ports).toContain('Certificato scaduto');
    expect(ports).toContain('Versioni TLS: TLS1.2, TLS1.0');
    expect(el(page, 'port-summary')!.textContent).toContain('chiuse 37');
    expect(el(page, 'port-summary')!.textContent).toContain('senza risposta 7');
    expect(el(page, 'protocols')!.textContent).toContain('JETDIRECT');
    expect(page.textContent).toContain('non verificati');
  });

  it('says when the ports of a device were never checked', async () => {
    const fixture = await setup();
    await open(fixture, PRINTER, { ...PRINTER, services: null });
    expect(el(fixture.nativeElement, 'ports-not-scanned')).not.toBeNull();
  });

  it('sets and clears the manual category and shows a confident disagreeing detection', async () => {
    const fixture = await setup();
    await open(fixture, PRINTER, { ...PRINTER, identifications: [], categoryHistory: [] });
    const page = fixture.nativeElement as HTMLElement;
    const select = el(page, 'category-select') as HTMLSelectElement;
    select.value = 'NAS';
    select.dispatchEvent(new Event('change'));
    const put = await nextRequest(http, '/api/v1/devices/d1/category');
    expect(put.request.method).toBe('PUT');
    expect(put.request.body).toEqual({ category: 'NAS' });
    put.flush({ ...PRINTER, category: 'NAS', manualCategory: 'NAS', suggestedCategory: 'PRINTER', identifications: [],
      categoryHistory: [] });
    await settle();
    fixture.detectChanges();
    expect(el(page, 'suggestion')!.textContent).toContain('Stampante');
    expect(el(page, 'inventory')!.textContent).toContain('manuale');

    const reset = el(page, 'category-select') as HTMLSelectElement;
    reset.value = '';
    reset.dispatchEvent(new Event('change'));
    const clear = await nextRequest(http, '/api/v1/devices/d1/category');
    expect(clear.request.body).toEqual({ category: null });
    clear.flush({ ...PRINTER, identifications: [], categoryHistory: [] });
  });

  it('explains randomized MACs and links them to the probable same device', async () => {
    const fixture = await setup();
    await open(fixture, PHONE, { ...PHONE, identifications: [], categoryHistory: [] });
    expect(el(fixture.nativeElement, 'randomized-note')!.textContent).toContain('MAC casuale');
    expect(el(fixture.nativeElement, 'same-as')!.textContent).toContain('Probabilmente è lo stesso dispositivo di "Mock-Phone"');
  });

  it('lists every interface and the IPv4/IPv6 address history', async () => {
    const fixture = await setup();
    await open(fixture, PRINTER, {
      ...PRINTER, identifications: [], categoryHistory: [],
      interfaces: [
        { mac: '00:11:22:00:60:10', macRandomized: false, vendor: 'MOCK Printers', agentInterface: 'eth0', current: true,
          firstSeenAt: '2026-11-17T10:00:00Z', lastSeenAt: '2026-11-18T10:00:00Z' },
        { mac: 'da:a1:19:00:60:11', macRandomized: true, vendor: null, agentInterface: 'wlan0', current: false,
          firstSeenAt: '2026-11-17T10:00:00Z', lastSeenAt: '2026-11-17T10:00:00Z' },
      ],
      addressHistory: [
        { address: '192.168.60.20', family: 4, scope: 'PRIVATE', interfaceId: null, eui64Mac: null,
          mac: '00:11:22:00:60:10', current: true, firstSeenAt: '2026-11-18T10:00:00Z', lastSeenAt: '2026-11-18T10:00:00Z', timesSeen: 1 },
        { address: 'fd00:60::211:22ff:fe00:6010', family: 6, scope: 'UNIQUE_LOCAL', interfaceId: 'EUI64',
          eui64Mac: '00:11:22:00:60:10', mac: '00:11:22:00:60:10', current: true, firstSeenAt: '2026-11-17T10:00:00Z',
          lastSeenAt: '2026-11-18T10:00:00Z', timesSeen: 2 },
        { address: '192.168.60.10', family: 4, scope: 'PRIVATE', interfaceId: null, eui64Mac: null,
          mac: '00:11:22:00:60:10', current: false, firstSeenAt: '2026-11-17T10:00:00Z', lastSeenAt: '2026-11-17T10:00:00Z', timesSeen: 1 },
      ],
    });
    const page = fixture.nativeElement as HTMLElement;
    const interfaces = el(page, 'interfaces')!.textContent!;
    expect(interfaces).toContain('00:11:22:00:60:10');
    expect(interfaces).toContain('wlan0');
    expect(interfaces).toContain('MAC casuale');
    const addresses = el(page, 'addresses')!.textContent!;
    expect(addresses).toContain('fd00:60::211:22ff:fe00:6010');
    expect(addresses).toContain('IPv6');
    expect(addresses).toContain('locale univoco (ULA)');
    expect(addresses).toContain('derivato dal MAC (EUI-64)');
    expect(addresses).toContain('attuale');
    expect(addresses).toContain('non più visto');
  });

  it('merges a probable same device only after confirmation, or dismisses the hint', async () => {
    const fixture = await setup();
    await open(fixture, PHONE, { ...PHONE, identifications: [], categoryHistory: [] });
    const page = fixture.nativeElement as HTMLElement;

    el(page, 'merge')!.click();
    fixture.detectChanges();
    expect(el(page, 'same-as')!.textContent).toContain('non è reversibile');
    el(page, 'merge-confirm')!.click();
    const merge = await nextRequest(http, '/api/v1/devices/d2/merge');
    expect(merge.request.method).toBe('POST');
    expect(merge.request.body).toEqual({ intoDeviceId: 'd3' });
    merge.flush({ ...OLD_PHONE, identifications: [], categoryHistory: [] });
    await settle();
    fixture.detectChanges();
    expect(el(page, 'inventory')!.textContent).not.toContain('da:a1:19:00:60:30');

    await open(fixture, OLD_PHONE, { ...OLD_PHONE, probableSameAs: 'd1', identifications: [], categoryHistory: [] });
    el(page, 'dismiss-same-as')!.click();
    const dismiss = await nextRequest(http, '/api/v1/devices/d3/same-as/dismiss');
    expect(dismiss.request.body).toEqual({ otherDeviceId: 'd1' });
    dismiss.flush({ ...OLD_PHONE, identifications: [], categoryHistory: [] });
    await settle();
    fixture.detectChanges();
    expect(el(page, 'same-as')).toBeNull();
  });

  it('shows the device card with status per field, confirms a value and keeps a custom name', async () => {
    const fixture = await setup();
    const card: Device = {
      ...PRINTER, identifications: [], categoryHistory: [],
      identity: [
        { field: 'MANUFACTURER', value: 'MOCK Printers', status: 'VERIFIED', confidence: 'MEDIUM', sources: ['IPP'],
          userConfirmed: false, conflict: false },
        { field: 'FIRMWARE', value: '1.0', status: 'PROBABLE', confidence: 'MEDIUM', sources: ['HOME_ASSISTANT'],
          userConfirmed: false, conflict: false },
        { field: 'CPE', value: null, status: 'UNKNOWN', confidence: null, sources: [], userConfirmed: false,
          conflict: false },
      ],
      identificationHistory: [{ field: 'FIRMWARE', oldValue: '0.9', newValue: '1.0', oldStatus: 'PROBABLE',
        newStatus: 'PROBABLE', origin: 'SCAN', scanId: 's1', changedAt: '2026-11-18T10:00:00Z' }],
    };
    await open(fixture, PRINTER, card);
    const page = fixture.nativeElement as HTMLElement;
    const identity = el(page, 'identity')!;
    expect(identity.querySelector('[data-status="VERIFIED"]')!.textContent).toContain('Verificato');
    expect(identity.querySelector('[data-status="PROBABLE"]')!.textContent).toContain('Probabile');
    expect(identity.querySelector('[data-status="UNKNOWN"]')!.textContent).toContain('Sconosciuto');
    expect(el(page, 'identification-history')!.textContent).toContain('0.9');

    el(page, 'confirm-FIRMWARE')!.click();
    const confirm = await nextRequest(http, '/api/v1/devices/d1/identity');
    expect(confirm.request.method).toBe('PUT');
    expect(confirm.request.body).toEqual({ field: 'FIRMWARE', value: '1.0' });
    confirm.flush({ ...card, identity: [{ ...card.identity![1], status: 'VERIFIED', userConfirmed: true }] });
    await settle();
    fixture.detectChanges();
    expect(el(page, 'identity')!.textContent).toContain('Confermato da te');

    (el(page, 'custom-name') as HTMLInputElement).value = ' Stampante studio ';
    el(page, 'custom-name-save')!.click();
    const rename = await nextRequest(http, '/api/v1/devices/d1/name');
    expect(rename.request.body).toEqual({ name: 'Stampante studio' });
    rename.flush({ ...card, customName: 'Stampante studio', displayName: 'Stampante studio' });
    await settle();
    fixture.detectChanges();
    expect(el(page, 'inventory')!.textContent).toContain('Stampante studio');
  });

  it('hides the classification from read-only users', async () => {
    const fixture = await setup([...ME.permissions, 'device:read']);
    await open(fixture, PRINTER, { ...PRINTER, identifications: [], categoryHistory: [] });
    expect(el(fixture.nativeElement, 'category-select')).toBeNull();
    expect(el(fixture.nativeElement, 'custom-name')).toBeNull();
  });

  it('shows the people of the devices and lets the user confirm, remove and assign', async () => {
    // [MOCK] people
    const marco: Person = { id: 'p1', homeId: 'h1', name: 'Marco', origin: 'DEVICE_NAME', createdAt: '2026-11-19T10:00:00Z',
      devices: [{ deviceId: 'd2', status: 'PROBABLE', source: 'DEVICE_NAME', evidence: 'iPhone-di-Marco', updatedAt: '2026-11-19T10:00:00Z' }] };
    const fixture = await setup([...ME.permissions, 'device:read', 'person:read', 'person:manage'], [marco]);
    const page = fixture.nativeElement as HTMLElement;
    expect(el(page, 'people-d2')!.textContent).toContain('Marco');
    expect(el(page, 'people-d2')!.textContent).toContain('probabile');
    expect(el(page, 'people-d1')!.textContent).toContain('—');
    expect(el(page, 'home-people')!.textContent).toContain('dal nome del dispositivo');

    await open(fixture, PHONE, PHONE);
    expect(el(page, 'device-people')!.textContent).toContain('iPhone-di-Marco');
    el(page, 'person-confirm-p1')!.click();
    const confirm = await nextRequest(http, '/api/v1/devices/d2/people/p1');
    expect(confirm.request.method).toBe('PUT');
    confirm.flush({ ...marco, devices: [{ ...marco.devices[0], status: 'CONFIRMED', source: 'USER' }] });
    await settle();
    fixture.detectChanges();
    expect(el(page, 'device-people')!.textContent).toContain('Confermata');
    expect(el(page, 'person-confirm-p1')).toBeNull();

    el(page, 'person-remove-p1')!.click();
    const remove = await nextRequest(http, '/api/v1/devices/d2/people/p1');
    expect(remove.request.method).toBe('DELETE');
    remove.flush({ ...marco, devices: [] });
    await settle();
    fixture.detectChanges();
    expect(el(page, 'device-people')!.textContent).toContain('Nessuna persona associata');

    (el(page, 'person-new') as HTMLInputElement).value = ' Luca ';
    el(page, 'person-create')!.click();
    const create = await nextRequest(http, '/api/v1/homes/h1/people');
    expect(create.request.body).toEqual({ name: 'Luca' });
    const luca: Person = { ...marco, id: 'p2', name: 'Luca', origin: 'USER', devices: [] };
    create.flush(luca);
    const assign = await nextRequest(http, '/api/v1/devices/d2/people/p2');
    expect(assign.request.method).toBe('PUT');
    assign.flush({ ...luca, devices: [{ deviceId: 'd2', status: 'CONFIRMED', source: 'USER', evidence: null, updatedAt: '2026-11-19T11:00:00Z' }] });
    await settle();
    fixture.detectChanges();
    expect(el(page, 'people-d2')!.textContent).toContain('Luca');

    el(page, 'person-delete-p2')!.click();
    const del = await nextRequest(http, '/api/v1/people/p2');
    expect(del.request.method).toBe('DELETE');
    del.flush(null);
    await settle();
    fixture.detectChanges();
    expect(el(page, 'people-d2')!.textContent).not.toContain('Luca');
  });

  it('hides people without person:read', async () => {
    const fixture = await setup();
    expect(el(fixture.nativeElement, 'people-d1')).toBeNull();
    expect(el(fixture.nativeElement, 'home-people')).toBeNull();
  });
});

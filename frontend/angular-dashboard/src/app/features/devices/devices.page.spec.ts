import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { signal } from '@angular/core';
import { provideRouter } from '@angular/router';
import { AuthService } from '../../core/auth/auth.service';
import { Device } from '../../core/devices/devices.api';
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
const OLD_PHONE: Device = { ...PHONE, id: 'd3', mac: 'da:a1:19:00:60:31', probableSameAs: null, hostname: 'Mock-Phone' };

describe('DevicesPage', () => {
  let http: HttpTestingController;

  async function setup(permissions = [...ME.permissions, 'device:read', 'device:classify']) {
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
    await settle();
    fixture.detectChanges();
    return fixture;
  }

  const el = (root: HTMLElement, id: string) => root.querySelector<HTMLElement>(`[data-testid="${id}"]`);

  async function open(fixture: Awaited<ReturnType<typeof setup>>, device: Device, detail: Device) {
    const opening = fixture.componentInstance.open(device);
    (await nextRequest(http, `/api/v1/devices/${device.id}`)).flush(detail);
    await opening;
    fixture.detectChanges();
  }

  afterEach(() => http.verify());

  it('lists the inventory with category, confidence and randomized MACs', async () => {
    const fixture = await setup();
    const table = el(fixture.nativeElement, 'inventory')!.textContent!;
    expect(table).toContain('mock-printer');
    expect(table).toContain('Stampante');
    expect(table).toContain('alta');
    expect(table).toContain('Non identificato');
    expect(table).toContain('MAC casuale');
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
    expect(el(fixture.nativeElement, 'randomized-note')!.textContent).toContain('Probabilmente è lo stesso dispositivo di "Mock-Phone"');
  });

  it('hides the classification from read-only users', async () => {
    const fixture = await setup([...ME.permissions, 'device:read']);
    await open(fixture, PRINTER, { ...PRINTER, identifications: [], categoryHistory: [] });
    expect(el(fixture.nativeElement, 'category-select')).toBeNull();
  });
});

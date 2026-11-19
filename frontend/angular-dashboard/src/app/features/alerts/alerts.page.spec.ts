import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { Alert, AlertType, NotificationPreference } from '../../core/alerts/alerts.api';
import { nextRequest, settle } from '../../testing/http';
import { translocoTesting } from '../../testing/transloco-testing';
import { AlertPreferencesPage } from './alert-preferences.page';
import { AlertsPage } from './alerts.page';

// [MOCK] alerts of a fictitious home
const base: Alert = {
  id: 'a1', homeId: 'h1', homeName: 'Casa MOCK', deviceId: 'd1', type: 'NEW_FINDING', severity: 'HIGH', occurrences: 3,
  firstAt: '2026-11-18T09:00:00Z', lastAt: '2026-11-18T10:00:00Z', resolvedAt: null, readAt: null,
  payload: { titleKey: 'findings.rule.telnet-open.title', params: { port: 23 }, deviceName: 'mock-router',
    deviceIp: '192.168.60.1' },
};
const ALERTS: Alert[] = [
  base,
  { ...base, id: 'a2', type: 'SCORE_DROPPED', severity: 'MEDIUM', occurrences: 1, deviceId: null,
    payload: { score: 58, scoreChange: -15 }, readAt: '2026-11-18T10:05:00Z' },
  { ...base, id: 'a3', type: 'NEW_DEVICE', severity: 'LOW', occurrences: 1,
    payload: { count: 1, devices: [{ id: 'd9', name: 'mock-tv', ip: '192.168.60.9' }] } },
  { ...base, id: 'a4', type: 'AGENT_OFFLINE', severity: 'MEDIUM', occurrences: 1, deviceId: null,
    payload: { agentName: 'mock-agent' }, resolvedAt: '2026-11-18T10:30:00Z' },
];

describe('AlertsPage', () => {
  async function setup() {
    await TestBed.configureTestingModule({
      imports: [AlertsPage, translocoTesting()],
      providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])],
    }).compileComponents();
    const http = TestBed.inject(HttpTestingController);
    const fixture = TestBed.createComponent(AlertsPage);
    fixture.detectChanges();
    const list = await nextRequest(http, '/api/v1/alerts?unread=false&limit=100');
    list.flush(ALERTS);
    await settle();
    fixture.detectChanges();
    return { fixture, http, page: fixture.nativeElement as HTMLElement };
  }

  it('builds the texts from the payload, with occurrences, resolution and links', async () => {
    const { page, http } = await setup();
    const titles = [...page.querySelectorAll('[data-testid="alert-title"]')].map((e) => e.textContent!.trim());
    expect(titles).toEqual([
      'Nuovo problema: Telnet attivo sulla porta 23',
      'Il punteggio è sceso a 58/100 (-15 punti)',
      'Nuovo dispositivo in rete: mock-tv',
      'Agent "mock-agent" non raggiungibile da più di 15 minuti',
    ]);
    const first = page.querySelector('[data-testid="alert-a1"]')!;
    expect(first.classList).toContain('unread');
    expect(first.textContent).toContain('Ripetuto 3 volte');
    expect(first.textContent).toContain('mock-router (192.168.60.1)');
    expect(first.querySelector('a')!.getAttribute('href')).toBe('/homes/h1/findings');
    expect(page.querySelector('[data-testid="alert-a2"] a')!.getAttribute('href')).toBe('/homes/h1/risk');
    expect(page.querySelector('[data-testid="alert-a2"] [data-testid="read"]')).toBeNull(); // already read
    expect(page.querySelector('[data-testid="alert-a4"] [data-testid="resolved"]')).not.toBeNull();
    http.verify();
  });

  it('marks an alert read and refreshes the unread counter', async () => {
    const { fixture, page, http } = await setup();
    (page.querySelector('[data-testid="alert-a1"] [data-testid="read"]') as HTMLButtonElement).click();
    const read = await nextRequest(http, '/api/v1/alerts/a1/read');
    expect(read.request.method).toBe('POST');
    read.flush(null, { status: 204, statusText: 'No Content' });
    (await nextRequest(http, '/api/v1/alerts/unread-count')).flush({ count: 1 });
    await settle();
    fixture.detectChanges();
    expect(page.querySelector('[data-testid="alert-a1"]')!.classList).not.toContain('unread');
    http.verify();
  });
});

describe('AlertPreferencesPage', () => {
  const TYPES: AlertType[] = ['NEW_FINDING', 'FINDING_RESOLVED', 'SCORE_DROPPED', 'NEW_DEVICE', 'SCAN_FAILED',
    'AGENT_OFFLINE'];
  const PREFS: NotificationPreference[] = TYPES.flatMap((type): NotificationPreference[] => [
    { type, channel: 'DASHBOARD', enabled: true, minSeverity: 'INFO' },
    { type, channel: 'EMAIL', enabled: true, minSeverity: 'MEDIUM' },
  ]);

  it('changes channel and minimum severity per type and saves them all', async () => {
    await TestBed.configureTestingModule({
      imports: [AlertPreferencesPage, translocoTesting()],
      providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])],
    }).compileComponents();
    const http = TestBed.inject(HttpTestingController);
    const fixture = TestBed.createComponent(AlertPreferencesPage);
    fixture.detectChanges();
    (await nextRequest(http, '/api/v1/notification-preferences')).flush(PREFS);
    await settle();
    fixture.detectChanges();
    const page = fixture.nativeElement as HTMLElement;
    expect(page.querySelectorAll('[data-testid="preferences"] tbody tr')).toHaveLength(6);

    const min = page.querySelector('[data-testid="NEW_DEVICE-EMAIL-min"]') as HTMLSelectElement;
    min.value = 'LOW';
    min.dispatchEvent(new Event('change'));
    const off = page.querySelector('[data-testid="FINDING_RESOLVED-DASHBOARD-enabled"]') as HTMLInputElement;
    off.checked = false;
    off.dispatchEvent(new Event('change'));
    fixture.detectChanges();
    (page.querySelector('[data-testid="save"]') as HTMLButtonElement).click();

    const put = await nextRequest(http, '/api/v1/notification-preferences');
    expect(put.request.method).toBe('PUT');
    const items = put.request.body.items as NotificationPreference[];
    expect(items).toHaveLength(12);
    expect(items).toContainEqual({ type: 'NEW_DEVICE', channel: 'EMAIL', enabled: true, minSeverity: 'LOW' });
    expect(items).toContainEqual({ type: 'FINDING_RESOLVED', channel: 'DASHBOARD', enabled: false, minSeverity: 'INFO' });
    put.flush(items);
    await settle();
    fixture.detectChanges();
    expect(page.querySelector('[data-testid="saved"]')).not.toBeNull();
    http.verify();
  });
});

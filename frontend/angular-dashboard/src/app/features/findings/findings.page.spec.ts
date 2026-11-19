import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { signal } from '@angular/core';
import { provideRouter } from '@angular/router';
import { AuthService } from '../../core/auth/auth.service';
import { Finding, FindingDetail } from '../../core/findings/findings.api';
import { ME } from '../../testing/auth-fixtures';
import { nextRequest, settle } from '../../testing/http';
import { translocoTesting } from '../../testing/transloco-testing';
import { FindingsPage } from './findings.page';

// [MOCK] findings (CVE-2099-*: not real vulnerabilities)
const CVE: Finding = {
  id: 'f1', homeId: 'h1', device: { id: 'd1', name: 'mock-camera', ip: '192.168.60.20', category: 'IP_CAMERA' },
  ruleId: 'cve.version-match', ruleVersion: 1, titleKey: 'findings.rule.cve-version-match.title',
  recommendationKey: 'findings.rule.cve-version-match.recommendation',
  params: { cve: 'CVE-2099-1001', product: 'OpenSSH', version: '7.2p1', cvss: '7.5', kev: 1 },
  severity: 'CRITICAL', type: 'CONFIRMED_VULNERABILITY', confidence: 'HIGH', source: 'CVE_MATCH', protocol: 'TCP',
  port: 22, cveId: 'CVE-2099-1001', status: 'OPEN', statusReason: null, statusChangedAt: null,
  firstDetectedAt: '2026-11-18T10:00:00Z', lastDetectedAt: '2026-11-18T10:00:00Z', resolvedAt: null, lastScanId: 's1',
};
const TELNET: Finding = {
  ...CVE, id: 'f2', ruleId: 'telnet.open', titleKey: 'findings.rule.telnet-open.title',
  recommendationKey: 'findings.rule.telnet-open.recommendation', params: { port: 23 }, severity: 'HIGH',
  type: 'SUSPICIOUS_CONFIGURATION', source: 'PORTSCAN', port: 23, cveId: null, status: 'RESOLVED',
  resolvedAt: '2026-11-18T11:00:00Z',
};
const RISK: Finding = {
  ...CVE, id: 'f3', params: { cve: 'CVE-2099-1003', product: 'nginx', version: '1.18.0' }, severity: 'MEDIUM',
  type: 'POTENTIAL_RISK', confidence: 'MEDIUM', port: 80, cveId: 'CVE-2099-1003',
};

const DETAIL: FindingDetail = {
  finding: CVE,
  evidence: [{ scanId: 's1', type: 'CVE_MATCH', data: { product: 'OpenSSH', matchQuality: 'EXACT_VERSION' },
    collectedAt: '2026-11-18T10:00:00Z' }],
  vulnerabilities: [{ cveId: 'CVE-2099-1001', matchQuality: 'EXACT_VERSION', matchedCpe: 'cpe:2.3:a:openbsd:openssh:7.2:p1',
    product: 'OpenSSH', version: '7.2p1', severity: 'HIGH', cvssScore: 7.5, cvssVersion: '3.1',
    description: 'MOCK vulnerability', kev: true, kevDateAdded: '2099-01-03', epssScore: 0.42, epssPercentile: 0.97 }],
  matchedCves: 1,
};

describe('FindingsPage', () => {
  let http: HttpTestingController;

  async function setup(permissions = [...ME.permissions, 'finding:read', 'finding:triage']) {
    await TestBed.configureTestingModule({
      imports: [FindingsPage, translocoTesting()],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideRouter([]),
        { provide: AuthService, useValue: { hasPermission: (p: string) => permissions.includes(p), me: signal(ME) } },
      ],
    }).compileComponents();
    http = TestBed.inject(HttpTestingController);
    const fixture = TestBed.createComponent(FindingsPage);
    fixture.componentRef.setInput('id', 'h1');
    fixture.detectChanges();
    (await nextRequest(http, '/api/v1/homes/h1/findings')).flush([CVE, RISK, TELNET]);
    await settle();
    fixture.detectChanges();
    return fixture;
  }

  const el = (root: HTMLElement, id: string) => root.querySelector<HTMLElement>(`[data-testid="${id}"]`);

  async function open(fixture: Awaited<ReturnType<typeof setup>>, finding: Finding, detail: FindingDetail) {
    const opening = fixture.componentInstance.open(finding);
    (await nextRequest(http, `/api/v1/findings/${finding.id}`)).flush(detail);
    await opening;
    fixture.detectChanges();
  }

  afterEach(() => http.verify());

  it('lists findings with severity, type and status, a confirmed vulnerability apart from a potential risk', async () => {
    const fixture = await setup();
    const table = el(fixture.nativeElement, 'findings')!.textContent!;
    expect(table).toContain('CVE-2099-1001 in OpenSSH 7.2p1');
    expect(table).toContain('Vulnerabilità confermata');
    expect(table).toContain('Rischio potenziale');
    expect(table).toContain('Telnet attivo sulla porta 23');
    expect(table).toContain('Risolto');
    expect(table).toContain('Critica');
  });

  it('filters by status, severity and type', async () => {
    const fixture = await setup();
    fixture.componentInstance.severity.set('CRITICAL');
    fixture.componentInstance.type.set('CONFIRMED_VULNERABILITY');
    const loading = fixture.componentInstance.load();
    const req = await nextRequest(http, '/api/v1/homes/h1/findings?severity=CRITICAL&type=CONFIRMED_VULNERABILITY');
    req.flush([CVE]);
    await loading;
    fixture.detectChanges();
    expect(el(fixture.nativeElement, 'findings')!.textContent).not.toContain('Telnet');
  });

  it('explains the finding, what to do, the evidence and the matched CVEs', async () => {
    const fixture = await setup();
    await open(fixture, CVE, DETAIL);
    const page = fixture.nativeElement as HTMLElement;
    expect(el(page, 'type-explanation')!.textContent).toContain('letta direttamente dal protocollo');
    expect(el(page, 'meaning')!.textContent).toContain('vulnerabilità nota');
    expect(el(page, 'recommendation')!.textContent).toContain('Aggiorna il firmware');
    const cves = el(page, 'cves')!.textContent!;
    expect(cves).toContain('CVE-2099-1001');
    expect(cves).toContain('Sfruttata attivamente');
    expect(cves).toContain('versione esatta');
    expect(cves).toContain('42%');
    expect(el(page, 'evidence')!.textContent).toContain('matchQuality: EXACT_VERSION');
  });

  it('requires a reason to mark a false positive and sends the triage', async () => {
    const fixture = await setup();
    await open(fixture, CVE, DETAIL);
    const page = fixture.nativeElement as HTMLElement;
    fixture.componentInstance.target.set('FALSE_POSITIVE');
    fixture.detectChanges();
    const submit = el(page, 'triage-form')!.querySelector('button')!;
    expect(submit.disabled).toBe(true);
    fixture.componentInstance.reason.set('MOCK: servizio non esposto');
    fixture.detectChanges();
    expect(submit.disabled).toBe(false);

    const saving = fixture.componentInstance.triage(DETAIL);
    const patch = await nextRequest(http, '/api/v1/findings/f1/status');
    expect(patch.request.method).toBe('PATCH');
    expect(patch.request.body).toEqual({ status: 'FALSE_POSITIVE', reason: 'MOCK: servizio non esposto' });
    patch.flush({ ...DETAIL, finding: { ...CVE, status: 'FALSE_POSITIVE', statusReason: 'MOCK: servizio non esposto' } });
    await saving;
    fixture.detectChanges();
    expect(el(page, 'status-reason')!.textContent).toContain('MOCK: servizio non esposto');
    expect(el(page, 'findings')!.textContent).toContain('Falso positivo');
  });

  it('shows the API error of a refused triage', async () => {
    const fixture = await setup();
    await open(fixture, CVE, DETAIL);
    const saving = fixture.componentInstance.triage(DETAIL);
    (await nextRequest(http, '/api/v1/findings/f1/status')).flush(
      { code: 'REASON_REQUIRED', message: 'A reason is required.' }, { status: 400, statusText: 'Bad Request' });
    await saving;
    fixture.detectChanges();
    expect(fixture.nativeElement.textContent).toContain('Indica una motivazione.');
  });

  it('offers no triage on resolved findings nor to read-only users', async () => {
    const fixture = await setup();
    await open(fixture, TELNET, { ...DETAIL, finding: TELNET, vulnerabilities: [], matchedCves: 0 });
    expect(el(fixture.nativeElement, 'triage-form')).toBeNull();
    TestBed.resetTestingModule();

    const readOnly = await setup([...ME.permissions, 'finding:read']);
    await open(readOnly, CVE, DETAIL);
    expect(el(readOnly.nativeElement, 'triage-form')).toBeNull();
  });
});

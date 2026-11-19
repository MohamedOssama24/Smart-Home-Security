import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { RiskHistoryEntry, RiskOverview, RiskSnapshot } from '../../core/risk/risk.api';
import { nextRequest, settle } from '../../testing/http';
import { translocoTesting } from '../../testing/transloco-testing';
import { RiskPage } from './risk.page';

// [MOCK] risk snapshots (CVE-2099-*: not real vulnerabilities)
const SNAPSHOT: RiskSnapshot = {
  id: 'r2', homeId: 'h1', scanId: 's2', scanProfile: 'STANDARD', trigger: 'SCAN', score: 55, riskLevel: 'HIGH',
  rating: 'POOR', notComputedReason: null, coverage: 0.813, provisional: false,
  coverageDetail: {
    profile: 'STANDARD', hostsDiscovered: 3, hostsAnalyzed: 3, hostRatio: 1, depth: 0.85,
    techniques: { ARP: true, ICMP: true, MDNS: false, SSDP: true }, techniqueScore: 0.8, routerIntegration: false,
    components: { hosts: 0.4, depth: 0.213, techniques: 0.16, router: 0 },
  },
  breakdown: {
    totalDeduction: 45, uncappedScore: 55, deviceCap: 45, deductionsCount: 2, notScored: 1, excludedCount: 1,
    deductions: [
      { findingId: 'f1', deviceId: 'd1', ruleId: 'cve.version-match', titleKey: 'findings.rule.cve-version-match.title',
        params: { cve: 'CVE-2099-1001', product: 'OpenSSH', version: '7.2p1' }, severity: 'CRITICAL',
        type: 'CONFIRMED_VULNERABILITY', confidence: 'HIGH', status: 'OPEN',
        factors: { base: 30, type: 1, confidence: 1, criticality: 1.3, exposure: 1.5, kev: 1.5 }, value: 87.75 },
      { findingId: 'f2', deviceId: 'd1', ruleId: 'telnet.open', titleKey: 'findings.rule.telnet-open.title',
        params: { port: 23 }, severity: 'HIGH', type: 'SUSPICIOUS_CONFIGURATION', confidence: 'HIGH', status: 'OPEN',
        factors: { base: 15, type: 0.5, confidence: 1, criticality: 1.3, exposure: 1.5, kev: 1 }, value: 14.63 },
    ],
    devices: [{ deviceId: 'd1', name: 'mock-router', ip: '192.168.60.1', category: 'ROUTER', criticality: 1.3,
      exposed: true, raw: 102.38, applied: 45, capped: true, findings: 2 }],
    excluded: [{ findingId: 'f3', titleKey: 'findings.rule.telnet-open.title', params: { port: 2323 },
      severity: 'HIGH', status: 'FALSE_POSITIVE' }],
  },
  topDevices: [{ deviceId: 'd1', name: 'mock-router', ip: '192.168.60.1', category: 'ROUTER', criticality: 1.3,
    exposed: true, raw: 102.38, applied: 45, capped: true, findings: 2 }],
  delta: {
    previousSnapshotId: 'r1', previousScanId: 's1', previousScore: 62, scoreChange: -7, coverageChange: 0,
    newFindingsCount: 1, newFindings: [{ findingId: 'f2', titleKey: 'findings.rule.telnet-open.title',
      params: { port: 23 }, severity: 'HIGH', value: 14.63 }],
    removedFindingsCount: 1, removedFindings: [{ findingId: 'f9', titleKey: 'findings.rule.ftp-cleartext.title',
      params: { port: 21 }, severity: 'HIGH', value: 7.5, status: 'RESOLVED' }],
    newDevicesCount: 0, newDevices: [],
  },
  computedAt: '2026-11-18T10:00:00Z', engineVersion: '2026.11-1',
};

const HISTORY: RiskHistoryEntry[] = [
  { id: 'r2', scanId: 's2', scanProfile: 'STANDARD', trigger: 'SCAN', score: 55, riskLevel: 'HIGH', rating: 'POOR',
    notComputedReason: null, coverage: 0.813, provisional: false, scoreChange: -7, computedAt: '2026-11-18T10:00:00Z',
    engineVersion: '2026.11-1' },
  { id: 'r1', scanId: 's1', scanProfile: 'QUICK', trigger: 'SCAN', score: 62, riskLevel: 'HIGH', rating: 'POOR',
    notComputedReason: null, coverage: 0.43, provisional: true, scoreChange: null, computedAt: '2026-11-17T10:00:00Z',
    engineVersion: '2026.11-1' },
];

describe('RiskPage', () => {
  let http: HttpTestingController;

  async function setup(overview: RiskOverview, history: RiskHistoryEntry[] = HISTORY) {
    await TestBed.configureTestingModule({
      imports: [RiskPage, translocoTesting()],
      providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])],
    }).compileComponents();
    http = TestBed.inject(HttpTestingController);
    const fixture = TestBed.createComponent(RiskPage);
    fixture.componentRef.setInput('id', 'h1');
    fixture.detectChanges();
    (await nextRequest(http, '/api/v1/homes/h1/risk')).flush(overview);
    (await nextRequest(http, '/api/v1/homes/h1/risk/history')).flush(history);
    await settle();
    fixture.detectChanges();
    return fixture.nativeElement as HTMLElement;
  }

  const el = (root: HTMLElement, id: string) => root.querySelector<HTMLElement>(`[data-testid="${id}"]`);

  afterEach(() => http.verify());

  it('shows the score, why it is that score, the riskiest devices, the changes and the history', async () => {
    const page = await setup({ current: SNAPSHOT, lastScored: SNAPSHOT });
    expect(el(page, 'score')!.textContent).toContain('55');
    expect(el(page, 'level')!.textContent).toContain('Rischio alto');
    expect(el(page, 'rating')!.textContent).toContain('Scarso');
    expect(el(page, 'delta')!.textContent).toContain('-7 punti rispetto al punteggio precedente (62)');
    expect(el(page, 'coverage')!.textContent).toContain('Copertura: 81%');
    expect(el(page, 'coverage')!.textContent).toContain('MDNS ✗');
    const why = el(page, 'deductions')!.textContent!;
    expect(why).toContain('CVE-2099-1001 in OpenSSH 7.2p1');
    expect(why).toContain('30 × 1 × 1 × 1.3 × 1.5 × 1.5');
    expect(why).toContain('mock-router');
    expect(el(page, 'capped')).not.toBeNull();
    expect(el(page, 'excluded')!.textContent).toContain('Falso positivo');
    expect(el(page, 'top-devices')!.textContent).toContain('Esposto a Internet');
    expect(el(page, 'removed')!.textContent).toContain('risolto (non più rilevato)');
    expect(el(page, 'history')!.textContent).toContain('*'); // provisional entry
    expect(el(page, 'provisional')).toBeNull();
  });

  it('marks a low-coverage score as provisional and explains the cap', async () => {
    const low: RiskSnapshot = { ...SNAPSHOT, score: 70, riskLevel: 'MEDIUM', rating: 'FAIR', coverage: 0.43,
      provisional: true, breakdown: { ...SNAPSHOT.breakdown, uncappedScore: 100, provisionalCap: 70, deductions: [],
        devices: [], deductionsCount: 0 }, topDevices: [], delta: null };
    const page = await setup({ current: low, lastScored: low }, []);
    expect(el(page, 'provisional')!.textContent).toContain('limitato a 70 (senza limite sarebbe 100)');
    expect(el(page, 'coverage-hint')).not.toBeNull();
    expect(el(page, 'no-deductions')).not.toBeNull();
    expect(el(page, 'history')).toBeNull();
  });

  it('after a discovery-only scan says why there is no score and shows the last computed one', async () => {
    const discovery: RiskSnapshot = { ...SNAPSHOT, id: 'r3', scanProfile: 'DISCOVERY', score: null, riskLevel: null,
      rating: null, notComputedReason: 'PORT_SCAN_REQUIRED', breakdown: {}, topDevices: [], delta: null };
    const page = await setup({ current: discovery, lastScored: SNAPSHOT });
    expect(el(page, 'not-computed')!.textContent).toContain('non controlla porte e servizi');
    expect(el(page, 'score')!.textContent).toContain('55');
  });

  it('without any scan asks to run one', async () => {
    const page = await setup({ current: null, lastScored: null }, []);
    expect(el(page, 'no-score')!.textContent).toContain('esegui una scansione');
    expect(el(page, 'score')).toBeNull();
  });
});

import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { HomeVulnerability } from '../../core/findings/findings.api';
import { nextRequest, settle } from '../../testing/http';
import { translocoTesting } from '../../testing/transloco-testing';
import { VulnerabilitiesPage } from './vulnerabilities.page';

// [MOCK] CVEs (CVE-2099-*: not real vulnerabilities)
const base: HomeVulnerability = {
  cveId: 'CVE-2099-0001', severity: 'MEDIUM', cvssScore: 5.3, kev: false, epssScore: 0.01, matchQuality: 'VERSION_RANGE',
  product: 'MOCK httpd', version: '2.4.1', device: { id: 'd1', name: 'mock-nas', ip: '192.168.60.20', category: 'NAS' },
  findingId: 'f1', findingStatus: 'OPEN', findingType: 'POTENTIAL_RISK',
};
const CVES: HomeVulnerability[] = [
  base,
  { ...base, cveId: 'CVE-2099-0002', severity: 'CRITICAL', cvssScore: 9.8, findingId: 'f2' },
  { ...base, cveId: 'CVE-2099-0003', severity: 'HIGH', cvssScore: 7.5, kev: true, findingId: 'f3',
    matchQuality: 'EXACT_VERSION', findingType: 'CONFIRMED_VULNERABILITY', findingStatus: 'ACKNOWLEDGED' },
];

describe('VulnerabilitiesPage', () => {
  async function setup(cves: HomeVulnerability[]) {
    await TestBed.configureTestingModule({
      imports: [VulnerabilitiesPage, translocoTesting()],
      providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])],
    }).compileComponents();
    const http = TestBed.inject(HttpTestingController);
    const fixture = TestBed.createComponent(VulnerabilitiesPage);
    fixture.componentRef.setInput('id', 'h1');
    fixture.detectChanges();
    (await nextRequest(http, '/api/v1/homes/h1/vulnerabilities')).flush(cves);
    await settle();
    fixture.detectChanges();
    http.verify();
    return { fixture, page: fixture.nativeElement as HTMLElement };
  }

  const rows = (page: HTMLElement) =>
    [...page.querySelectorAll('[data-testid="cves"] tbody tr')].map((r) => r.querySelector('a')!.textContent!.trim());

  it('lists KEV first, then by CVSS, with match quality, device and finding status; filters', async () => {
    const { fixture, page } = await setup(CVES);
    expect(rows(page)).toEqual(['CVE-2099-0003', 'CVE-2099-0002', 'CVE-2099-0001']);
    const first = page.querySelector('[data-testid="cves"] tbody tr')!.textContent!;
    expect(first).toContain('Sfruttata attivamente');
    expect(first).toContain('versione esatta');
    expect(first).toContain('mock-nas');
    expect(first).toContain('Preso in carico');
    expect(page.querySelector('[data-testid="cves"] a')!.getAttribute('rel')).toContain('noopener');

    fixture.componentInstance.kevOnly.set(true);
    fixture.detectChanges();
    expect(rows(page)).toEqual(['CVE-2099-0003']);
    fixture.componentInstance.kevOnly.set(false);
    fixture.componentInstance.severity.set('CRITICAL');
    fixture.detectChanges();
    expect(rows(page)).toEqual(['CVE-2099-0002']);
    expect(page.querySelector('[data-testid="count"]')!.textContent).toContain('1 di 3');
  });

  it('says when no CVE is matched', async () => {
    const { page } = await setup([]);
    expect(page.querySelector('[data-testid="no-cves"]')).not.toBeNull();
  });
});

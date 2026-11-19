import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { HomeOverview } from '../../core/overview/overview.api';
import { nextRequest, settle } from '../../testing/http';
import { translocoTesting } from '../../testing/transloco-testing';
import { OverviewPage } from './overview.page';

// [MOCK] homes
const SAFE: HomeOverview = {
  homeId: 'h1', name: 'Casa al mare', customerId: null,
  security: { score: 92, riskLevel: 'LOW', rating: 'EXCELLENT', provisional: false, coverage: 0.85, scoreChange: 4,
    computedAt: '2026-11-18T09:00:00Z', notComputedReason: null, openFindings: { LOW: 1 }, kevFindings: 0, devices: 6,
    lastScanAt: '2026-11-18T09:00:00Z' },
};
const RISKY: HomeOverview = {
  homeId: 'h2', name: 'Casa in città', customerId: null,
  security: { score: 38, riskLevel: 'CRITICAL', rating: 'CRITICAL', provisional: true, coverage: 0.5, scoreChange: -12,
    computedAt: '2026-11-18T08:00:00Z', notComputedReason: 'PORT_SCAN_REQUIRED',
    openFindings: { CRITICAL: 1, HIGH: 2, MEDIUM: 1 }, kevFindings: 1, devices: 9, lastScanAt: '2026-11-18T10:00:00Z' },
};
const NEW: HomeOverview = {
  homeId: 'h3', name: 'Casa nuova', customerId: null,
  security: { score: null, riskLevel: null, rating: null, provisional: false, coverage: null, scoreChange: null,
    computedAt: null, notComputedReason: null, openFindings: {}, kevFindings: 0, devices: 0, lastScanAt: null },
};
const RESTRICTED: HomeOverview = { homeId: 'h4', name: 'Casa del cliente', customerId: 'c1', security: null };

describe('OverviewPage', () => {
  async function setup(homes: HomeOverview[]) {
    await TestBed.configureTestingModule({
      imports: [OverviewPage, translocoTesting()],
      providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])],
    }).compileComponents();
    const http = TestBed.inject(HttpTestingController);
    const fixture = TestBed.createComponent(OverviewPage);
    fixture.detectChanges();
    (await nextRequest(http, '/api/v1/overview')).flush(homes);
    await settle();
    fixture.detectChanges();
    http.verify();
    return fixture.nativeElement as HTMLElement;
  }

  const el = (root: HTMLElement, id: string) => root.querySelector<HTMLElement>(`[data-testid="${id}"]`);

  it('lists the homes riskiest first with score, findings, KEV and a summary', async () => {
    const page = await setup([SAFE, NEW, RESTRICTED, RISKY]);
    const cards = [...page.querySelectorAll('[data-testid^="home-"]')].map((c) => c.getAttribute('data-testid'));
    expect(cards).toEqual(['home-h2', 'home-h1', 'home-h3', 'home-h4']);
    const risky = el(page, 'home-h2')!;
    expect(el(risky, 'score')!.textContent).toContain('38');
    expect(risky.textContent).toContain('Rischio critico');
    expect(el(risky, 'provisional')).not.toBeNull();
    expect(el(risky, 'not-computed')!.textContent).toContain('Solo rilevamento');
    expect(el(risky, 'change')!.textContent).toContain('-12');
    expect(el(risky, 'findings')!.textContent).toContain('1 Critica');
    expect(el(risky, 'kev')!.textContent).toContain('1 KEV');
    expect(el(el(page, 'home-h3')!, 'no-score')).not.toBeNull();
    expect(el(el(page, 'home-h4')!, 'restricted')).not.toBeNull();
    const summary = el(page, 'summary')!.textContent!;
    expect(summary).toMatch(/4\s*abitazioni/);
    expect(summary).toMatch(/1\s*a rischio alto o critico/);
    expect(summary).toMatch(/3\s*problemi critici o alti/);
    expect(summary).toMatch(/1\s*senza punteggio/);
  });

  it('without homes points to the homes page', async () => {
    const page = await setup([]);
    expect(el(page, 'no-homes')).not.toBeNull();
    expect(el(page, 'homes')).toBeNull();
  });
});

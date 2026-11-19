import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { AuthService } from '../../core/auth/auth.service';
import { Report } from '../../core/reports/reports.api';
import { nextRequest, settle } from '../../testing/http';
import { translocoTesting } from '../../testing/transloco-testing';
import { ReportsPage } from './reports.page';

// [MOCK] scans and reports of a fictitious home
const scan = (id: string, status: string, completedAt: string | null) => ({
  id, homeId: 'h1', agentId: 'a1', trigger: 'MANUAL', profile: 'STANDARD', status, requestedBy: 'u1',
  requestedAt: '2026-11-18T09:00:00Z', queuedAt: null, startedAt: null, completedAt, cancelRequestedAt: null,
  progress: null, devicesDiscovered: 3, outOfScopeDropped: 0, warnings: [], failureReason: null, targets: null,
  events: null,
});
const SCANS = [scan('s2', 'FAILED', null), scan('s1', 'COMPLETED', '2026-11-18T09:10:00Z')];
const READY: Report = {
  id: 'r0', homeId: 'h1', scanId: 's1', locale: 'it', status: 'READY', errorCode: null, sizeBytes: 20480, pages: 2,
  sha256: 'a'.repeat(64), requestedAt: '2026-11-18T09:20:00Z', generatedAt: '2026-11-18T09:20:02Z',
};

describe('ReportsPage', () => {
  async function setup(permissions: string[]) {
    await TestBed.configureTestingModule({
      imports: [ReportsPage, translocoTesting()],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideRouter([]),
        { provide: AuthService, useValue: { hasPermission: (p: string) => permissions.includes(p), me: signal(null) } },
      ],
    }).compileComponents();
    const http = TestBed.inject(HttpTestingController);
    const fixture = TestBed.createComponent(ReportsPage);
    fixture.componentRef.setInput('id', 'h1');
    fixture.componentInstance.pollMs = 0;
    fixture.detectChanges();
    (await nextRequest(http, '/api/v1/homes/h1/reports')).flush([READY]);
    (await nextRequest(http, '/api/v1/homes/h1/scans')).flush(SCANS);
    await settle();
    fixture.detectChanges();
    return { fixture, http, page: fixture.nativeElement as HTMLElement };
  }

  it('generates a report of a completed scan, follows it until ready and downloads the PDF', async () => {
    const { fixture, http, page } = await setup(['report:generate']);
    const options = [...page.querySelectorAll('[data-testid="scan"] option')].map((o) => (o as HTMLOptionElement).value);
    expect(options).toEqual(['s1']); // completed scans only
    const locale = page.querySelector('[data-testid="locale"]') as HTMLSelectElement;
    locale.value = 'en';
    locale.dispatchEvent(new Event('change'));
    (page.querySelector('[data-testid="generate"]') as HTMLButtonElement).click();

    const post = await nextRequest(http, '/api/v1/scans/s1/reports');
    expect(post.request.method).toBe('POST');
    expect(post.request.body).toEqual({ locale: 'en' });
    const pending: Report = {
      ...READY, id: 'r1', locale: 'en', status: 'PENDING', sizeBytes: null, pages: null, sha256: null, generatedAt: null,
    };
    post.flush(pending);
    await settle();
    fixture.detectChanges();
    expect(page.querySelector('[data-testid="report-r1"] [data-testid="status"]')!.textContent).toContain('In preparazione');

    (await nextRequest(http, '/api/v1/reports/r1')).flush({ ...READY, id: 'r1', locale: 'en' });
    await settle();
    fixture.detectChanges();
    const row = page.querySelector('[data-testid="report-r1"]')!;
    expect(row.textContent).toContain('Pronto');
    expect(row.textContent).toContain('2 pagine, 20 KB');

    const createObjectURL = vi.fn(() => 'blob:mock');
    Object.assign(URL, { createObjectURL, revokeObjectURL: vi.fn() });
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => undefined);
    (row.querySelector('[data-testid="download"]') as HTMLButtonElement).click();
    const download = await nextRequest(http, '/api/v1/reports/r1/download');
    expect(download.request.responseType).toBe('blob');
    download.flush(new Blob(['%PDF-1.7 MOCK'], { type: 'application/pdf' }));
    await settle();
    expect(createObjectURL).toHaveBeenCalled();
    expect(click).toHaveBeenCalled();
    click.mockRestore();
    http.verify();
  });

  it('without report:generate shows the reports but no generation form', async () => {
    const { page, http } = await setup([]);
    expect(page.querySelector('[data-testid="generate-form"]')).toBeNull();
    expect(page.querySelector('[data-testid="report-r0"] [data-testid="download"]')).not.toBeNull();
    http.verify();
  });
});

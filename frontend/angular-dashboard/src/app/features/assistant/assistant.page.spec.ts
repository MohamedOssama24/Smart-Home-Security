import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { AssistantAnswer } from '../../core/assistant/assistant.api';
import { nextRequest, settle } from '../../testing/http';
import { translocoTesting } from '../../testing/transloco-testing';
import { AssistantPage } from './assistant.page';

// [MOCK] answer about a fictitious home
const ANSWER: AssistantAnswer = {
  answer: 'Prima di tutto: Telnet attivo sulla porta 23 [F1].',
  citations: [{ id: 'F1', kind: 'FINDING', label: 'Telnet attivo sulla porta 23', severity: 'CRITICAL', ip: '192.168.50.10' }],
  provider: 'LOCAL',
  fallback: false,
  fallbackReason: null,
  scanId: 's1',
  dataAsOf: '2026-11-18T09:10:00Z',
  generatedAt: '2026-11-18T09:20:00Z',
};

describe('AssistantPage', () => {
  async function setup() {
    await TestBed.configureTestingModule({
      imports: [AssistantPage, translocoTesting()],
      providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])],
    }).compileComponents();
    const http = TestBed.inject(HttpTestingController);
    const fixture = TestBed.createComponent(AssistantPage);
    fixture.componentRef.setInput('id', 'h1');
    fixture.detectChanges();
    await settle();
    return { fixture, http, page: fixture.nativeElement as HTMLElement };
  }

  async function ask(fixture: { detectChanges(): void }, page: HTMLElement, text: string) {
    const box = page.querySelector('[data-testid="question"]') as HTMLTextAreaElement;
    box.value = text;
    box.dispatchEvent(new Event('input'));
    fixture.detectChanges();
    (page.querySelector('[data-testid="ask"]') as HTMLButtonElement).click();
  }

  it('sends the question and shows the answer with its sources, nothing is requested before', async () => {
    const { fixture, http, page } = await setup();
    http.expectNone('/api/v1/homes/h1/assistant/questions');
    expect(page.querySelector('[data-testid="disclaimer"]')!.textContent).toContain('Non esegue azioni');

    await ask(fixture, page, '  Cosa sistemo per primo?  ');
    const post = await nextRequest(http, '/api/v1/homes/h1/assistant/questions');
    expect(post.request.method).toBe('POST');
    expect(post.request.body).toEqual({ question: 'Cosa sistemo per primo?', locale: 'it' });
    post.flush(ANSWER);
    await settle();
    fixture.detectChanges();

    expect(page.querySelector('[data-testid="answer"]')!.textContent).toContain('Telnet attivo sulla porta 23 [F1]');
    expect(page.querySelector('[data-testid="citation-F1"]')!.textContent).toContain('problema');
    expect(page.querySelector('[data-testid="meta"]')!.textContent).toContain('LOCAL');
    expect(page.querySelector('[data-testid="fallback"]')).toBeNull();
    http.verify();
  });

  it('shows when the AI answer was replaced and reports errors', async () => {
    const { fixture, http, page } = await setup();
    await ask(fixture, page, 'Rischio?');
    (await nextRequest(http, '/api/v1/homes/h1/assistant/questions'))
      .flush({ ...ANSWER, provider: 'LOCAL', fallback: true, fallbackReason: 'NOT_GROUNDED' });
    await settle();
    fixture.detectChanges();
    expect(page.querySelector('[data-testid="fallback"]')!.textContent).toContain('non era supportata dai dati');

    await ask(fixture, page, 'Rischio?');
    (await nextRequest(http, '/api/v1/homes/h1/assistant/questions'))
      .flush({ title: 'Too many requests' }, { status: 429, statusText: 'Too Many Requests' });
    await settle();
    fixture.detectChanges();
    expect(page.querySelector('[data-testid="problem"]')).not.toBeNull();
    expect(page.querySelector('[data-testid="answer"]')).toBeNull();
  });
});

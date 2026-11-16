import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { App } from './app';
import { translocoTesting } from './testing/transloco-testing';

describe('App', () => {
  beforeEach(async () => {
    localStorage.clear();
    await TestBed.configureTestingModule({
      imports: [App, translocoTesting()],
      providers: [provideRouter([]), provideHttpClient(), provideHttpClientTesting()],
    }).compileComponents();
  });

  it('renders the brand and both languages', async () => {
    const fixture = TestBed.createComponent(App);
    await fixture.whenStable();
    const element = fixture.nativeElement as HTMLElement;

    expect(element.querySelector('.brand')?.textContent).toContain('Smart Home Security Check');
    const options = Array.from(element.querySelectorAll('option')).map((o) => o.value);
    expect(options).toEqual(['it', 'en']);
  });

  it('switches language from the selector', async () => {
    const fixture = TestBed.createComponent(App);
    await fixture.whenStable();
    const select = (fixture.nativeElement as HTMLElement).querySelector('select') as HTMLSelectElement;

    select.value = 'en';
    select.dispatchEvent(new Event('change'));
    fixture.detectChanges();
    await fixture.whenStable();

    expect(document.documentElement.lang).toBe('en');
    expect(select.selectedOptions[0]?.textContent).toContain('English');
  });
});

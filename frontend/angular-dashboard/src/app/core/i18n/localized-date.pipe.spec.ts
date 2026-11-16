import { TestBed } from '@angular/core/testing';
import { signal } from '@angular/core';
import { LanguageService } from './language.service';
import { LocalizedDatePipe } from './localized-date.pipe';

describe('LocalizedDatePipe', () => {
  const current = signal<'it' | 'en'>('it');

  function pipe(): LocalizedDatePipe {
    TestBed.configureTestingModule({
      providers: [LocalizedDatePipe, { provide: LanguageService, useValue: { current } }],
    });
    return TestBed.inject(LocalizedDatePipe);
  }

  beforeEach(() => current.set('it'));

  it('formats dates in the language chosen in the UI, not in en-US', () => {
    const p = pipe();
    // midday UTC: the same calendar day in every time zone the tests may run in
    expect(p.transform('2026-11-16T12:00:00Z', 'mediumDate')).toBe('16 nov 2026');

    current.set('en');
    expect(p.transform('2026-11-16T12:00:00Z', 'mediumDate')).toBe('Nov 16, 2026');
  });

  it('renders nothing for missing values', () => {
    const p = pipe();
    expect(p.transform(null)).toBe('');
    expect(p.transform(undefined)).toBe('');
  });
});

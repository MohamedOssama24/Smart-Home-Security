import { TestBed } from '@angular/core/testing';
import { TranslocoService } from '@jsverse/transloco';
import { LanguageService, isSupportedLanguage, resolveInitialLanguage } from './language.service';
import { translocoTesting } from '../../testing/transloco-testing';

describe('resolveInitialLanguage', () => {
  it('prefers a saved supported language', () => {
    expect(resolveInitialLanguage('en', 'it-IT')).toBe('en');
  });

  it('ignores an unsupported saved value and uses the browser language', () => {
    expect(resolveInitialLanguage('fr', 'en-GB')).toBe('en');
  });

  it('falls back to Italian when nothing matches', () => {
    expect(resolveInitialLanguage(null, 'de-DE')).toBe('it');
    expect(resolveInitialLanguage(null, undefined)).toBe('it');
  });
});

describe('isSupportedLanguage', () => {
  it('accepts only it and en', () => {
    expect(isSupportedLanguage('it')).toBe(true);
    expect(isSupportedLanguage('en')).toBe(true);
    expect(isSupportedLanguage('EN')).toBe(false);
    expect(isSupportedLanguage(42)).toBe(false);
  });
});

describe('LanguageService', () => {
  beforeEach(() => {
    localStorage.clear();
    TestBed.configureTestingModule({ imports: [translocoTesting()] });
  });

  it('switches Transloco, the document lang and persists the choice', () => {
    const service = TestBed.inject(LanguageService);
    const transloco = TestBed.inject(TranslocoService);

    service.use('en');

    expect(service.current()).toBe('en');
    expect(transloco.getActiveLang()).toBe('en');
    expect(document.documentElement.lang).toBe('en');
    expect(localStorage.getItem('shsc.lang')).toBe('en');
  });

  it('restores the saved language on init', () => {
    localStorage.setItem('shsc.lang', 'en');
    const service = TestBed.inject(LanguageService);

    service.init();

    expect(service.current()).toBe('en');
  });
});

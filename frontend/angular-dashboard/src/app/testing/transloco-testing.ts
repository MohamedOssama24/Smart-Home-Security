import { TranslocoTestingModule, TranslocoTestingOptions } from '@jsverse/transloco';
import it from '../../../public/i18n/it.json';
import en from '../../../public/i18n/en.json';

/** Transloco with the real translation files, loaded synchronously for tests. */
export function translocoTesting(options: TranslocoTestingOptions = {}) {
  return TranslocoTestingModule.forRoot({
    langs: { it, en },
    translocoConfig: { availableLangs: ['it', 'en'], defaultLang: 'it' },
    preloadLangs: true,
    ...options,
  });
}

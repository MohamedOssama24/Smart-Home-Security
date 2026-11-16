import { formatDate, registerLocaleData } from '@angular/common';
import localeIt from '@angular/common/locales/it';
import { Pipe, PipeTransform, inject } from '@angular/core';
import { LanguageService } from './language.service';

// Angular ships only en-US locale data; Italian must be registered to format dates in Italian.
registerLocaleData(localeIt);

/**
 * Formats a date in the language currently chosen in the UI (the built-in DatePipe uses the
 * static LOCALE_ID, which would always print en-US dates).
 * Impure on purpose: the result changes when the user switches language; reading the
 * language signal also schedules a refresh of OnPush views.
 */
@Pipe({ name: 'appDate', pure: false })
export class LocalizedDatePipe implements PipeTransform {
  private readonly language = inject(LanguageService);

  transform(value: string | number | Date | null | undefined, format = 'mediumDate'): string {
    if (value === null || value === undefined || value === '') {
      return '';
    }
    return formatDate(value, format, this.language.current());
  }
}

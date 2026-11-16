import { Injectable, inject, signal } from '@angular/core';
import { DOCUMENT } from '@angular/common';
import { TranslocoService } from '@jsverse/transloco';

export const SUPPORTED_LANGUAGES = ['it', 'en'] as const;
export type Language = (typeof SUPPORTED_LANGUAGES)[number];

const STORAGE_KEY = 'shsc.lang';

export function isSupportedLanguage(value: unknown): value is Language {
  return typeof value === 'string' && (SUPPORTED_LANGUAGES as readonly string[]).includes(value);
}

/** Picks the initial language: saved preference, then browser language, then Italian. */
export function resolveInitialLanguage(saved: string | null, browserLanguage: string | undefined): Language {
  if (isSupportedLanguage(saved)) {
    return saved;
  }
  const browser = browserLanguage?.slice(0, 2).toLowerCase();
  return isSupportedLanguage(browser) ? browser : 'it';
}

@Injectable({ providedIn: 'root' })
export class LanguageService {
  private readonly transloco = inject(TranslocoService);
  private readonly document = inject(DOCUMENT);

  readonly current = signal<Language>('it');

  init(): void {
    const language = resolveInitialLanguage(this.readSaved(), this.document.defaultView?.navigator.language);
    this.apply(language);
  }

  use(language: Language): void {
    this.apply(language);
    this.save(language);
  }

  private apply(language: Language): void {
    this.current.set(language);
    this.transloco.setActiveLang(language);
    this.document.documentElement.lang = language;
  }

  // Storage can be unavailable (private mode, blocked site data): the preference is only a convenience.
  private readSaved(): string | null {
    try {
      return this.document.defaultView?.localStorage.getItem(STORAGE_KEY) ?? null;
    } catch {
      return null;
    }
  }

  private save(language: Language): void {
    try {
      this.document.defaultView?.localStorage.setItem(STORAGE_KEY, language);
    } catch {
      // Preference not persisted; the language still applies for this session.
    }
  }
}

import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { Router, RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import { TranslocoPipe } from '@jsverse/transloco';
import { hasTenantWidePermission } from './core/auth/auth.models';
import { AuthService } from './core/auth/auth.service';
import { LanguageService, SUPPORTED_LANGUAGES, isSupportedLanguage } from './core/i18n/language.service';

@Component({
  selector: 'app-root',
  imports: [RouterOutlet, RouterLink, RouterLinkActive, TranslocoPipe],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './app.html',
  styleUrl: './app.scss',
})
export class App {
  protected readonly language = inject(LanguageService);
  protected readonly auth = inject(AuthService);
  private readonly router = inject(Router);
  protected readonly languages = SUPPORTED_LANGUAGES;

  constructor() {
    this.language.init();
  }

  /** Navigation hints only: every page and API call is authorized by the backend. */
  protected showUsers(): boolean {
    return hasTenantWidePermission(this.auth.me(), 'user:read');
  }

  protected showCustomers(): boolean {
    return this.auth.me()?.tenant.type === 'BUSINESS' && this.auth.hasPermission('customer:read');
  }

  protected onLanguageChange(value: string): void {
    if (isSupportedLanguage(value)) {
      this.language.use(value);
    }
  }

  protected async logout(): Promise<void> {
    try {
      await this.auth.logout();
    } finally {
      await this.router.navigateByUrl('/login');
    }
  }
}

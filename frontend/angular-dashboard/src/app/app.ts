import { ChangeDetectionStrategy, Component, effect, inject, signal } from '@angular/core';
import { NavigationEnd, Router, RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import { TranslocoPipe } from '@jsverse/transloco';
import { filter } from 'rxjs';
import { UnreadAlerts } from './core/alerts/alerts.api';
import { hasTenantWidePermission } from './core/auth/auth.models';
import { BrandingState } from './core/billing/billing.api';
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
  protected readonly unread = inject(UnreadAlerts);
  protected readonly branding = inject(BrandingState);
  private readonly router = inject(Router);
  protected readonly languages = SUPPORTED_LANGUAGES;
  /** Navigation menu on small screens (always visible on wide ones). */
  protected readonly menuOpen = signal(false);

  constructor() {
    this.language.init();
    // white label of the tenant (PRO plan): name, color and logo in the header
    effect(() => {
      if (this.auth.isAuthenticated()) {
        void this.branding.load();
      } else {
        this.branding.clear();
      }
    });
    // unread alerts next to the menu entry, refreshed at every page change
    this.router.events.pipe(filter((e) => e instanceof NavigationEnd)).subscribe(() => {
      if (this.auth.isAuthenticated()) {
        this.unread.refresh();
      }
    });
  }

  /** Navigation hints only: every page and API call is authorized by the backend. */
  protected showUsers(): boolean {
    return hasTenantWidePermission(this.auth.me(), 'user:read');
  }

  protected showBilling(): boolean {
    return hasTenantWidePermission(this.auth.me(), 'billing:manage');
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

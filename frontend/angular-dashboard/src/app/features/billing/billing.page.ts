import { ChangeDetectionStrategy, Component, OnInit, inject, input, signal } from '@angular/core';
import { TranslocoPipe } from '@jsverse/transloco';
import { firstValueFrom } from 'rxjs';
import { ApiProblem, toApiProblem } from '../../core/api/api-error';
import { BillingApi, BillingOverview, Branding, BrandingState, isStripeUrl } from '../../core/billing/billing.api';
import { LocalizedDatePipe } from '../../core/i18n/localized-date.pipe';

/**
 * Subscription of the tenant and white label (Milestone 17). Payments happen on Stripe Checkout /
 * Billing Portal: card data never passes through the dashboard. The plan changes only when the
 * backend receives the signed Stripe webhook.
 */
@Component({
  selector: 'app-billing-page',
  imports: [TranslocoPipe, LocalizedDatePipe],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <section class="card wide">
      <h1>{{ 'billing.title' | transloco }}</h1>
      @if (checkout() === 'success') {
        <div class="alert" role="status" data-testid="checkout-success">{{ 'billing.checkoutSuccess' | transloco }}</div>
      } @else if (checkout() === 'cancel') {
        <div class="alert" role="status" data-testid="checkout-cancel">{{ 'billing.checkoutCancel' | transloco }}</div>
      }
      @if (problem(); as p) {
        <div class="alert error" role="alert" data-testid="problem">{{ p.messageKey | transloco }}</div>
      }
      @if (overview(); as o) {
        <p data-testid="current-plan">{{ 'billing.currentPlan' | transloco }} <strong>{{ 'billing.plans.' + o.currentPlan | transloco }}</strong>
          @if (o.subscription; as s) {
            · {{ 'billing.status.' + s.status | transloco }}
            @if (s.status === 'trialing' && s.trialEnd) {
              · <span data-testid="trial-end">{{ 'billing.trialEndsOn' | transloco }} {{ s.trialEnd | appDate: 'mediumDate' }}</span>
            } @else if (s.currentPeriodEnd) {
              · {{ (s.cancelAtPeriodEnd ? 'billing.endsOn' : 'billing.renewsOn') | transloco }} {{ s.currentPeriodEnd | appDate: 'mediumDate' }}
            }
          }
        </p>
        @if (!o.enabled) {
          <p class="muted" data-testid="disabled">{{ 'billing.disabled' | transloco }}</p>
        }
        <div class="plans">
          @for (p of o.plans; track p.code) {
            <article class="card" [attr.data-testid]="'plan-' + p.code" [class.current]="p.code === o.currentPlan">
              <h2>{{ 'billing.plans.' + p.code | transloco }}</h2>
              <ul class="small">
                <li>{{ 'billing.limits.homes' | transloco }}: {{ p.maxHomes ?? '∞' }}</li>
                <li>{{ 'billing.limits.users' | transloco }}: {{ p.maxUsers ?? '∞' }}</li>
                @if (o.tenantType === 'BUSINESS') {
                  <li>{{ 'billing.limits.customers' | transloco }}: {{ p.maxCustomers ?? '∞' }}</li>
                }
                <li>{{ 'billing.limits.agents' | transloco }}: {{ p.maxAgentsPerHome ?? '∞' }}</li>
                <li>{{ 'billing.limits.scans' | transloco }}: {{ p.maxScansPerDay ?? '∞' }}</li>
                @if (p.whiteLabel) {
                  <li>{{ 'billing.limits.whiteLabel' | transloco }}</li>
                }
              </ul>
              @if (o.enabled && p.code !== 'FREE' && p.code !== o.currentPlan && !hasSubscription(o)) {
                @if (o.trialDays) {
                  <p class="small" [attr.data-testid]="'trial-' + p.code">{{ 'billing.trialOffer' | transloco: { days: o.trialDays } }}</p>
                }
                <button type="button" class="primary" (click)="subscribe(p.code)" [disabled]="busy()"
                        [attr.data-testid]="'subscribe-' + p.code">{{ 'billing.subscribe' | transloco }}</button>
              }
            </article>
          }
        </div>
        @if (o.enabled && o.subscription) {
          <button type="button" (click)="portal()" [disabled]="busy()" data-testid="portal">{{ 'billing.portal' | transloco }}</button>
        }
        <p class="small muted">{{ 'billing.note' | transloco }}</p>
      }
    </section>

    @if (overview()?.tenantType === 'BUSINESS' && branding(); as b) {
      <section class="card wide" data-testid="branding">
        <h2>{{ 'branding.title' | transloco }}</h2>
        @if (!b.available) {
          <p class="muted" data-testid="branding-unavailable">{{ 'branding.unavailable' | transloco }}</p>
        } @else {
          <form (submit)="$event.preventDefault(); saveBranding()">
            <label>{{ 'branding.displayName' | transloco }}
              <input maxlength="80" [value]="name()" (input)="name.set($any($event.target).value)" data-testid="brand-name" />
            </label>
            <label>{{ 'branding.primaryColor' | transloco }}
              <input type="color" [value]="color()" (input)="color.set($any($event.target).value)" data-testid="brand-color" />
            </label>
            <label>{{ 'branding.supportEmail' | transloco }}
              <input type="email" maxlength="254" [value]="email()" (input)="email.set($any($event.target).value)" />
            </label>
            <div class="actions">
              <button type="submit" class="primary" [disabled]="busy()" data-testid="brand-save">{{ 'branding.save' | transloco }}</button>
            </div>
          </form>
          <label>{{ 'branding.logo' | transloco }}
            <input type="file" accept="image/png,image/jpeg" (change)="uploadLogo($any($event.target).files)" data-testid="brand-logo" />
          </label>
          <p class="small muted">{{ 'branding.logoHint' | transloco }}</p>
          @if (b.logoSha256) {
            <button type="button" (click)="removeLogo()" [disabled]="busy()">{{ 'branding.removeLogo' | transloco }}</button>
          }
          @if (saved()) {
            <p class="small" role="status" data-testid="brand-saved">{{ 'branding.saved' | transloco }}</p>
          }
        }
      </section>
    }
  `,
  styles: `
    .plans { display: grid; gap: 1rem; grid-template-columns: repeat(auto-fit, minmax(14rem, 1fr)); margin: 1rem 0; }
    .plans .current { outline: 2px solid var(--primary); }
  `,
})
export class BillingPage implements OnInit {
  /** ?checkout=success|cancel when Stripe sends the user back (component input binding). */
  readonly checkout = input<string | undefined>();
  private readonly api = inject(BillingApi);
  private readonly brandingState = inject(BrandingState);

  readonly overview = signal<BillingOverview | null>(null);
  readonly branding = signal<Branding | null>(null);
  readonly problem = signal<ApiProblem | null>(null);
  readonly busy = signal(false);
  readonly saved = signal(false);
  readonly name = signal('');
  readonly color = signal('#1f5fbf');
  readonly email = signal('');

  async ngOnInit(): Promise<void> {
    try {
      this.overview.set(await firstValueFrom(this.api.overview()));
      if (this.overview()?.tenantType === 'BUSINESS') {
        this.setBranding(await firstValueFrom(this.api.branding()));
      }
    } catch (e) {
      this.problem.set(toApiProblem(e));
    }
  }

  protected hasSubscription(o: BillingOverview): boolean {
    return !!o.subscription && !['canceled', 'incomplete_expired'].includes(o.subscription.status);
  }

  async subscribe(planCode: string): Promise<void> {
    await this.go(() => this.api.checkout(planCode));
  }

  async portal(): Promise<void> {
    await this.go(() => this.api.portal());
  }

  async saveBranding(): Promise<void> {
    await this.run(async () => {
      const b = await firstValueFrom(this.api.updateBranding({
        displayName: this.name().trim() || null,
        primaryColor: this.color() || null,
        supportEmail: this.email().trim() || null,
      }));
      this.setBranding(b);
      this.saved.set(true);
    });
  }

  async uploadLogo(files: FileList | null): Promise<void> {
    const file = files?.item(0);
    if (!file) {
      return;
    }
    await this.run(async () => this.setBranding(await firstValueFrom(this.api.uploadLogo(file))));
  }

  async removeLogo(): Promise<void> {
    await this.run(async () => this.setBranding(await firstValueFrom(this.api.deleteLogo())));
  }

  /** Leaves the dashboard for Stripe (overridable in tests). */
  protected redirect(url: string): void {
    window.location.assign(url);
  }

  private async go(call: () => ReturnType<BillingApi['portal']>): Promise<void> {
    await this.run(async () => {
      const { url } = await firstValueFrom(call());
      if (!isStripeUrl(url)) {
        throw new Error('unexpected redirect');
      }
      this.redirect(url);
    });
  }

  private async run(action: () => Promise<void>): Promise<void> {
    this.busy.set(true);
    this.problem.set(null);
    this.saved.set(false);
    try {
      await action();
    } catch (e) {
      this.problem.set(toApiProblem(e));
    } finally {
      this.busy.set(false);
    }
  }

  private setBranding(b: Branding): void {
    this.branding.set(b);
    this.name.set(b.displayName ?? '');
    this.color.set(b.primaryColor ?? '#1f5fbf');
    this.email.set(b.supportEmail ?? '');
    void this.brandingState.apply(b);
  }
}

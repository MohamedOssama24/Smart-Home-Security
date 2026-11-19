import { HttpClient } from '@angular/common/http';
import { Injectable, inject, signal } from '@angular/core';
import { Observable, firstValueFrom } from 'rxjs';

export interface BillingPlan {
  code: string;
  description: string;
  tenantTypes: string[];
  whiteLabel: boolean;
  maxHomes: number | null;
  maxUsers: number | null;
  maxCustomers: number | null;
  maxNetworksPerHome: number | null;
  maxAgentsPerHome: number | null;
  maxScansPerDay: number | null;
}

export interface BillingOverview {
  enabled: boolean;
  tenantType: string;
  currentPlan: string;
  subscription: { planCode: string | null; status: string; currentPeriodEnd: string | null; cancelAtPeriodEnd: boolean; trialEnd?: string | null } | null;
  /** Free trial offered at checkout to this tenant (0 = none). */
  trialDays?: number;
  plans: BillingPlan[];
}

export interface Branding {
  available: boolean;
  displayName: string | null;
  primaryColor: string | null;
  supportEmail: string | null;
  logoSha256: string | null;
  updatedAt: string | null;
}

/** Subscription (Stripe Checkout / Billing Portal, Milestone 17): the state comes only from Stripe webhooks. */
@Injectable({ providedIn: 'root' })
export class BillingApi {
  private readonly http = inject(HttpClient);

  overview(): Observable<BillingOverview> {
    return this.http.get<BillingOverview>('/api/v1/billing');
  }

  checkout(planCode: string): Observable<{ url: string }> {
    return this.http.post<{ url: string }>('/api/v1/billing/checkout', { planCode });
  }

  portal(): Observable<{ url: string }> {
    return this.http.post<{ url: string }>('/api/v1/billing/portal', {});
  }

  branding(): Observable<Branding> {
    return this.http.get<Branding>('/api/v1/branding');
  }

  updateBranding(data: { displayName: string | null; primaryColor: string | null; supportEmail: string | null }): Observable<Branding> {
    return this.http.put<Branding>('/api/v1/branding', data);
  }

  uploadLogo(file: Blob): Observable<Branding> {
    return this.http.put<Branding>('/api/v1/branding/logo', file, { headers: { 'Content-Type': file.type } });
  }

  deleteLogo(): Observable<Branding> {
    return this.http.delete<Branding>('/api/v1/branding/logo');
  }

  logo(): Observable<Blob> {
    return this.http.get('/api/v1/branding/logo', { responseType: 'blob' });
  }
}

/** Only https URLs of Stripe are followed (the backend already checks them). */
export function isStripeUrl(url: string): boolean {
  try {
    const u = new URL(url);
    return u.protocol === 'https:' && (u.hostname === 'checkout.stripe.com' || u.hostname === 'billing.stripe.com');
  } catch {
    return false;
  }
}

/**
 * White label applied to the shell: name, primary color (CSS variable) and logo (data URL, allowed by
 * the CSP img-src). Empty when the plan does not include it.
 */
@Injectable({ providedIn: 'root' })
export class BrandingState {
  private readonly api = inject(BillingApi);
  readonly name = signal<string | null>(null);
  readonly logo = signal<string | null>(null);

  async load(): Promise<void> {
    try {
      this.apply(await firstValueFrom(this.api.branding()));
    } catch {
      this.apply(null);
    }
  }

  async apply(b: Branding | null): Promise<void> {
    const active = b?.available ? b : null;
    this.name.set(active?.displayName ?? null);
    const root = document.documentElement.style;
    if (active?.primaryColor && /^#[0-9a-f]{6}$/.test(active.primaryColor)) {
      root.setProperty('--primary', active.primaryColor);
    } else {
      root.removeProperty('--primary');
    }
    if (!active?.logoSha256) {
      this.logo.set(null);
      return;
    }
    try {
      const blob = await firstValueFrom(this.api.logo());
      if (blob.type !== 'image/png' && blob.type !== 'image/jpeg') {
        this.logo.set(null);
        return;
      }
      this.logo.set(await toDataUrl(blob));
    } catch {
      this.logo.set(null);
    }
  }

  clear(): void {
    void this.apply(null);
  }
}

function toDataUrl(blob: Blob): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result));
    reader.onerror = () => reject(reader.error);
    reader.readAsDataURL(blob);
  });
}

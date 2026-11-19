import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { BillingOverview, Branding, isStripeUrl } from '../../core/billing/billing.api';
import { nextRequest, settle } from '../../testing/http';
import { translocoTesting } from '../../testing/transloco-testing';
import { BillingPage } from './billing.page';

// [MOCK] plans of a business tenant on FREE
const OVERVIEW: BillingOverview = {
  enabled: true,
  tenantType: 'BUSINESS',
  currentPlan: 'FREE',
  subscription: null,
  plans: [
    { code: 'FREE', description: 'Free', tenantTypes: ['INDIVIDUAL', 'BUSINESS'], whiteLabel: false, maxHomes: 2, maxUsers: 3,
      maxCustomers: 2, maxNetworksPerHome: 4, maxAgentsPerHome: 2, maxScansPerDay: 10 },
    { code: 'PRO', description: 'Pro', tenantTypes: ['BUSINESS'], whiteLabel: true, maxHomes: 50, maxUsers: 20,
      maxCustomers: 50, maxNetworksPerHome: 8, maxAgentsPerHome: 5, maxScansPerDay: 50 },
  ],
  trialDays: 14,
};
const NO_BRANDING: Branding = { available: false, displayName: null, primaryColor: null, supportEmail: null, logoSha256: null, updatedAt: null };

describe('BillingPage', () => {
  async function setup(checkout?: string) {
    await TestBed.configureTestingModule({
      imports: [BillingPage, translocoTesting()],
      providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])],
    }).compileComponents();
    const http = TestBed.inject(HttpTestingController);
    const fixture = TestBed.createComponent(BillingPage);
    if (checkout) {
      fixture.componentRef.setInput('checkout', checkout);
    }
    const redirects: string[] = [];
    (fixture.componentInstance as unknown as { redirect: (u: string) => void }).redirect = (u) => redirects.push(u);
    fixture.detectChanges();
    (await nextRequest(http, '/api/v1/billing')).flush(OVERVIEW);
    (await nextRequest(http, '/api/v1/branding')).flush(NO_BRANDING);
    await settle();
    fixture.detectChanges();
    return { fixture, http, redirects, page: fixture.nativeElement as HTMLElement };
  }

  it('starts a Stripe checkout for the plan and shows that white label needs Pro', async () => {
    const { fixture, http, redirects, page } = await setup('success');
    expect(page.querySelector('[data-testid="checkout-success"]')).not.toBeNull();
    expect(page.querySelector('[data-testid="subscribe-FREE"]')).toBeNull();
    expect(page.querySelector('[data-testid="portal"]')).toBeNull();
    expect(page.querySelector('[data-testid="branding-unavailable"]')).not.toBeNull();
    expect(page.querySelector('[data-testid="trial-PRO"]')?.textContent).toContain('14');

    (page.querySelector('[data-testid="subscribe-PRO"]') as HTMLButtonElement).click();
    const post = await nextRequest(http, '/api/v1/billing/checkout');
    expect(post.request.body).toEqual({ planCode: 'PRO' });
    post.flush({ url: 'https://checkout.stripe.com/c/pay/cs_test_MOCK' });
    await settle();
    fixture.detectChanges();
    expect(redirects).toEqual(['https://checkout.stripe.com/c/pay/cs_test_MOCK']);
  });

  it('never follows a redirect outside Stripe and shows API errors', async () => {
    const { fixture, http, redirects, page } = await setup();
    (page.querySelector('[data-testid="subscribe-PRO"]') as HTMLButtonElement).click();
    (await nextRequest(http, '/api/v1/billing/checkout')).flush({ url: 'https://evil.example/pay' });
    await settle();
    fixture.detectChanges();
    expect(redirects).toEqual([]);
    expect(page.querySelector('[data-testid="problem"]')).not.toBeNull();

    (page.querySelector('[data-testid="subscribe-PRO"]') as HTMLButtonElement).click();
    (await nextRequest(http, '/api/v1/billing/checkout')).flush(
      { code: 'BILLING_PROVIDER_ERROR', status: 502 }, { status: 502, statusText: 'Bad Gateway' });
    await settle();
    fixture.detectChanges();
    expect(page.querySelector('[data-testid="problem"]')!.textContent).toContain('pagamento');
    expect(isStripeUrl('http://checkout.stripe.com/x')).toBe(false);
    expect(isStripeUrl('https://billing.stripe.com/p/session/x')).toBe(true);
  });
});

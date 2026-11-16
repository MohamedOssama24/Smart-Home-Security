import { LocalizedDatePipe } from '../../core/i18n/localized-date.pipe';
import { ChangeDetectionStrategy, Component, OnInit, computed, inject, input, signal } from '@angular/core';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { TranslocoPipe } from '@jsverse/transloco';
import { firstValueFrom } from 'rxjs';
import { ApiProblem, toApiProblem } from '../../core/api/api-error';
import { TENANT_WIDE_SCOPES, hasTenantWidePermission } from '../../core/auth/auth.models';
import { AuthService } from '../../core/auth/auth.service';
import { Customer, CustomersApi } from '../../core/customers/customers.api';
import { Home, HomesApi } from '../../core/homes/homes.api';

@Component({
  selector: 'app-homes-page',
  imports: [ReactiveFormsModule, RouterLink, TranslocoPipe, LocalizedDatePipe],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <section class="card wide">
      <h1>{{ 'homes.title' | transloco }}</h1>
      @if (filteredCustomer(); as c) {
        <p class="muted" data-testid="customer-filter">
          {{ 'homes.ofCustomer' | transloco: { name: c.displayName } }} · <a routerLink="/homes">{{ 'homes.all' | transloco }}</a>
        </p>
      }
      @if (problem(); as p) {
        <div class="alert error" role="alert">{{ p.messageKey | transloco }}</div>
      }
      @if (homes().length === 0 && loaded()) {
        <!-- after a failed load the error above is enough; never invite to create without permission -->
        @if (!problem()) {
          <p class="muted" data-testid="no-homes">
            {{ (canCreate() ? 'homes.empty' : 'homes.emptyNoCreate') | transloco }}
          </p>
        }
      } @else {
        <table class="list">
          <tbody>
            @for (home of homes(); track home.id) {
              <tr>
                <td><a [routerLink]="['/homes', home.id]">{{ home.name }}</a></td>
                <td class="muted">{{ customerName(home.customerId) }}</td>
                <td class="muted">{{ home.createdAt | appDate: 'mediumDate' }}</td>
              </tr>
            }
          </tbody>
        </table>
      }
    </section>

    @if (canCreate()) {
      <section class="card wide">
        <h2>{{ 'homes.create.title' | transloco }}</h2>
        <form [formGroup]="form" (ngSubmit)="create()" novalidate>
          <div class="field">
            <label for="homeName">{{ 'homes.fields.name' | transloco }}</label>
            <input id="homeName" formControlName="name" [placeholder]="'homes.create.name' | transloco" />
          </div>
          @if (customers().length) {
            <div class="field">
              <label for="homeCustomer">{{ 'homes.fields.customer' | transloco }}</label>
              <select id="homeCustomer" formControlName="customerId">
                @if (tenantWide()) {
                  <option value="">{{ 'homes.fields.noCustomer' | transloco }}</option>
                }
                @for (customer of customers(); track customer.id) {
                  <option [value]="customer.id">{{ customer.displayName }}</option>
                }
              </select>
            </div>
          }
          <button class="primary" type="submit" [disabled]="busy() || form.invalid">
            {{ 'homes.create.submit' | transloco }}
          </button>
        </form>
      </section>
    }
  `,
})
export class HomesPage implements OnInit {
  private readonly api = inject(HomesApi);
  private readonly customersApi = inject(CustomersApi);
  private readonly auth = inject(AuthService);

  /** Optional filter from the query string (?customerId=...), bound by the router. */
  readonly customerId = input<string | undefined>(undefined);

  readonly homes = signal<Home[]>([]);
  readonly customers = signal<Customer[]>([]);
  readonly loaded = signal(false);
  readonly busy = signal(false);
  readonly problem = signal<ApiProblem | null>(null);
  readonly filteredCustomer = computed(() => this.customers().find((c) => c.id === this.customerId()) ?? null);
  readonly form = inject(FormBuilder).nonNullable.group({
    name: ['', [Validators.required, Validators.maxLength(100)]],
    customerId: [''],
  });

  tenantWide(): boolean {
    return hasTenantWidePermission(this.auth.me(), 'home:write');
  }

  /**
   * UI hint only, the backend decides: tenant-wide home:write, or home:write on a customer
   * (the home is then created for that customer).
   */
  canCreate(): boolean {
    const me = this.auth.me();
    if (!me || !this.auth.hasPermission('home:write')) {
      return false;
    }
    return me.roles.some((r) => TENANT_WIDE_SCOPES.includes(r.scopeType) || r.scopeType === 'CUSTOMER');
  }

  ngOnInit(): void {
    void this.load();
  }

  customerName(id: string | null): string {
    return id ? (this.customers().find((c) => c.id === id)?.displayName ?? '') : '';
  }

  async load(): Promise<void> {
    try {
      this.homes.set(await firstValueFrom(this.api.list(this.customerId())));
      if (this.auth.me()?.tenant.type === 'BUSINESS' && this.auth.hasPermission('customer:read')) {
        const customers = await firstValueFrom(this.customersApi.list());
        this.customers.set(customers);
        if (!this.tenantWide() && !this.form.controls.customerId.value && customers.length) {
          this.form.controls.customerId.setValue(customers[0].id);
        }
      }
    } catch (error) {
      this.problem.set(toApiProblem(error));
    } finally {
      this.loaded.set(true);
    }
  }

  async create(): Promise<void> {
    if (this.form.invalid || this.busy()) {
      return;
    }
    this.busy.set(true);
    this.problem.set(null);
    const value = this.form.getRawValue();
    try {
      await firstValueFrom(
        this.api.create({ name: value.name.trim(), customerId: value.customerId || null, address: null, timezone: null }),
      );
      this.form.controls.name.reset();
      await this.load();
    } catch (error) {
      this.problem.set(toApiProblem(error));
    } finally {
      this.busy.set(false);
    }
  }
}

import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { TranslocoPipe } from '@jsverse/transloco';
import { firstValueFrom } from 'rxjs';
import { ApiProblem, toApiProblem } from '../../core/api/api-error';
import { hasTenantWidePermission } from '../../core/auth/auth.models';
import { AuthService } from '../../core/auth/auth.service';
import { Organization, TenancyApi, TenantOverview } from '../../core/tenancy/tenancy.api';

/** Plan, usage and (for business tenants) the organization's details. */
@Component({
  selector: 'app-organization-page',
  imports: [ReactiveFormsModule, TranslocoPipe],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    @if (problem(); as p) {
      <div class="card wide"><div class="alert error" role="alert">{{ p.messageKey | transloco }}</div></div>
    }
    @if (tenant(); as t) {
      <section class="card wide">
        <h1>{{ t.name }}</h1>
        <h2>{{ 'organization.plan.title' | transloco: { plan: t.plan.code } }}</h2>
        <table class="list" data-testid="plan">
          <tbody>
            @for (row of planRows(t); track row.key) {
              <tr>
                <td>{{ 'organization.plan.' + row.key | transloco }}</td>
                <td>
                  @if (row.used !== null) {
                    {{ row.used }} /
                  }
                  {{ row.limit === null ? ('organization.plan.unlimited' | transloco) : row.limit }}
                </td>
              </tr>
            }
          </tbody>
        </table>
        <p class="muted">{{ 'organization.plan.note' | transloco }}</p>
      </section>
    }

    @if (organization(); as o) {
      <section class="card wide">
        <h2>{{ 'organization.details.title' | transloco }}</h2>
        @if (saved()) {
          <div class="alert success" role="status">{{ 'organization.details.saved' | transloco }}</div>
        }
        <form [formGroup]="form" (ngSubmit)="save()" novalidate>
          <div class="field">
            <label for="legalName">{{ 'organization.details.legalName' | transloco }}</label>
            <input id="legalName" formControlName="legalName" [readonly]="!canManage()" />
          </div>
          <div class="field">
            <label for="vatNumber">{{ 'organization.details.vatNumber' | transloco }}</label>
            <input id="vatNumber" formControlName="vatNumber" [readonly]="!canManage()" />
          </div>
          <div class="field">
            <label for="contactEmail">{{ 'organization.details.contactEmail' | transloco }}</label>
            <input id="contactEmail" type="email" formControlName="contactEmail" [readonly]="!canManage()" />
          </div>
          <div class="field">
            <label for="contactPhone">{{ 'organization.details.contactPhone' | transloco }}</label>
            <input id="contactPhone" type="tel" formControlName="contactPhone" [readonly]="!canManage()" />
          </div>
          @if (canManage()) {
            <button class="primary" type="submit" [disabled]="busy() || form.invalid">
              {{ 'common.save' | transloco }}
            </button>
          }
        </form>
      </section>
    }
  `,
})
export class OrganizationPage implements OnInit {
  private readonly api = inject(TenancyApi);
  private readonly auth = inject(AuthService);

  readonly tenant = signal<TenantOverview | null>(null);
  readonly organization = signal<Organization | null>(null);
  readonly busy = signal(false);
  readonly saved = signal(false);
  readonly problem = signal<ApiProblem | null>(null);
  readonly form = inject(FormBuilder).nonNullable.group({
    legalName: ['', [Validators.required, Validators.maxLength(200)]],
    vatNumber: ['', [Validators.maxLength(24), Validators.pattern(/^[A-Za-z0-9 ]*$/)]],
    contactEmail: ['', [Validators.email, Validators.maxLength(254)]],
    contactPhone: ['', [Validators.pattern(/^([+0-9 ()./-]{4,30})?$/)]],
  });

  canManage(): boolean {
    return hasTenantWidePermission(this.auth.me(), 'organization:manage');
  }

  planRows(t: TenantOverview): { key: string; used: number | null; limit: number | null }[] {
    const rows = [
      { key: 'homes', used: t.usage?.homes ?? null, limit: t.plan.maxHomes },
      { key: 'users', used: t.usage?.users ?? null, limit: t.plan.maxUsers },
    ];
    if (t.type === 'BUSINESS') {
      rows.push({ key: 'customers', used: t.usage?.customers ?? null, limit: t.plan.maxCustomers });
    }
    rows.push({ key: 'networksPerHome', used: null, limit: t.plan.maxNetworksPerHome });
    rows.push({ key: 'agentsPerHome', used: null, limit: t.plan.maxAgentsPerHome });
    rows.push({ key: 'scansPerDay', used: null, limit: t.plan.maxScansPerDay });
    return rows;
  }

  ngOnInit(): void {
    void this.load();
  }

  async load(): Promise<void> {
    try {
      const tenant = await firstValueFrom(this.api.current());
      this.tenant.set(tenant);
      if (tenant.type === 'BUSINESS') {
        this.show(await firstValueFrom(this.api.organization()));
      }
    } catch (error) {
      this.problem.set(toApiProblem(error));
    }
  }

  async save(): Promise<void> {
    if (this.form.invalid || this.busy() || !this.canManage()) {
      return;
    }
    this.busy.set(true);
    this.saved.set(false);
    this.problem.set(null);
    const value = this.form.getRawValue();
    try {
      this.show(
        await firstValueFrom(
          this.api.updateOrganization({
            legalName: value.legalName.trim(),
            vatNumber: blankToNull(value.vatNumber),
            contactEmail: blankToNull(value.contactEmail),
            contactPhone: blankToNull(value.contactPhone),
          }),
        ),
      );
      this.saved.set(true);
    } catch (error) {
      this.problem.set(toApiProblem(error));
    } finally {
      this.busy.set(false);
    }
  }

  private show(organization: Organization): void {
    this.organization.set(organization);
    this.form.setValue({
      legalName: organization.legalName,
      vatNumber: organization.vatNumber ?? '',
      contactEmail: organization.contactEmail ?? '',
      contactPhone: organization.contactPhone ?? '',
    });
  }
}

export function blankToNull(value: string): string | null {
  const trimmed = value.trim();
  return trimmed === '' ? null : trimmed;
}

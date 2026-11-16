import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { TranslocoPipe } from '@jsverse/transloco';
import { firstValueFrom } from 'rxjs';
import { ApiProblem, toApiProblem } from '../../core/api/api-error';
import { hasTenantWidePermission } from '../../core/auth/auth.models';
import { AuthService } from '../../core/auth/auth.service';
import { Customer, CustomersApi } from '../../core/customers/customers.api';
import { blankToNull } from '../organization/organization.page';

/** Customers of a business tenant (installer, MSP): list, create, edit, archive. */
@Component({
  selector: 'app-customers-page',
  imports: [ReactiveFormsModule, RouterLink, TranslocoPipe],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <section class="card wide">
      <h1>{{ 'customers.title' | transloco }}</h1>
      @if (problem(); as p) {
        <div class="alert error" role="alert">{{ p.messageKey | transloco }}</div>
      }
      @if (loaded() && customers().length === 0 && !problem()) {
        <p class="muted" data-testid="no-customers">{{ 'customers.empty' | transloco }}</p>
      }
      @if (customers().length) {
        <table class="list" data-testid="customers">
          <thead>
            <tr>
              <th>{{ 'customers.name' | transloco }}</th>
              <th>{{ 'customers.contact' | transloco }}</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            @for (customer of customers(); track customer.id) {
              <tr>
                <td>
                  <a [routerLink]="['/homes']" [queryParams]="{ customerId: customer.id }">{{ customer.displayName }}</a>
                </td>
                <td class="muted">{{ customer.contactEmail }} {{ customer.contactPhone }}</td>
                <td>
                  @if (canManage()) {
                    <div class="actions">
                      <button type="button" (click)="edit(customer)" [disabled]="busy()">
                        {{ 'common.edit' | transloco }}
                      </button>
                      @if (confirmingArchive() === customer.id) {
                        <span class="muted" role="status">{{ 'customers.archiveConfirm' | transloco }}</span>
                        <button type="button" class="danger" (click)="archive(customer)" [disabled]="busy()"
                                data-testid="confirm-archive">
                          {{ 'common.confirmArchive' | transloco }}
                        </button>
                        <button type="button" (click)="confirmingArchive.set(null)" [disabled]="busy()">
                          {{ 'common.cancel' | transloco }}
                        </button>
                      } @else {
                        <button type="button" class="danger" (click)="confirmingArchive.set(customer.id)"
                                [disabled]="busy()" data-testid="archive">
                          {{ 'common.archive' | transloco }}
                        </button>
                      }
                    </div>
                  }
                </td>
              </tr>
            }
          </tbody>
        </table>
      }
    </section>

    @if (canManage()) {
      <section class="card wide">
        <h2>{{ (editing() ? 'customers.editTitle' : 'customers.createTitle') | transloco }}</h2>
        <form [formGroup]="form" (ngSubmit)="save()" novalidate>
          <div class="field">
            <label for="customerName">{{ 'customers.name' | transloco }}</label>
            <input id="customerName" formControlName="displayName" />
          </div>
          <div class="field">
            <label for="customerEmail">{{ 'customers.email' | transloco }}</label>
            <input id="customerEmail" type="email" formControlName="contactEmail" />
          </div>
          <div class="field">
            <label for="customerPhone">{{ 'customers.phone' | transloco }}</label>
            <input id="customerPhone" type="tel" formControlName="contactPhone" />
          </div>
          <div class="field">
            <label for="customerNotes">{{ 'customers.notes' | transloco }}</label>
            <input id="customerNotes" formControlName="notes" />
            <span class="hint">{{ 'customers.notesHint' | transloco }}</span>
          </div>
          <div class="actions">
            <button class="primary" type="submit" [disabled]="busy() || form.invalid">
              {{ (editing() ? 'common.save' : 'customers.create') | transloco }}
            </button>
            @if (editing()) {
              <button type="button" (click)="cancelEdit()">{{ 'common.cancel' | transloco }}</button>
            }
          </div>
        </form>
      </section>
    }
  `,
})
export class CustomersPage implements OnInit {
  private readonly api = inject(CustomersApi);
  private readonly auth = inject(AuthService);

  readonly customers = signal<Customer[]>([]);
  readonly loaded = signal(false);
  readonly busy = signal(false);
  readonly editing = signal<Customer | null>(null);
  readonly confirmingArchive = signal<string | null>(null);
  readonly problem = signal<ApiProblem | null>(null);
  readonly form = inject(FormBuilder).nonNullable.group({
    displayName: ['', [Validators.required, Validators.maxLength(200)]],
    contactEmail: ['', [Validators.email, Validators.maxLength(254)]],
    contactPhone: ['', [Validators.pattern(/^([+0-9 ()./-]{4,30})?$/)]],
    notes: ['', [Validators.maxLength(1000)]],
  });

  /** UI hint only: the backend decides (tenant-wide customer:manage). */
  canManage(): boolean {
    return hasTenantWidePermission(this.auth.me(), 'customer:manage');
  }

  ngOnInit(): void {
    void this.load();
  }

  async load(): Promise<void> {
    try {
      this.customers.set(await firstValueFrom(this.api.list()));
    } catch (error) {
      this.problem.set(toApiProblem(error));
    } finally {
      this.loaded.set(true);
    }
  }

  edit(customer: Customer): void {
    this.editing.set(customer);
    this.form.setValue({
      displayName: customer.displayName,
      contactEmail: customer.contactEmail ?? '',
      contactPhone: customer.contactPhone ?? '',
      notes: customer.notes ?? '',
    });
  }

  cancelEdit(): void {
    this.editing.set(null);
    this.form.reset();
  }

  async save(): Promise<void> {
    if (this.form.invalid) {
      return;
    }
    const value = this.form.getRawValue();
    const data = {
      displayName: value.displayName.trim(),
      contactEmail: blankToNull(value.contactEmail),
      contactPhone: blankToNull(value.contactPhone),
      notes: blankToNull(value.notes),
    };
    const editing = this.editing();
    await this.run(async () => {
      await firstValueFrom(editing ? this.api.update(editing.id, data) : this.api.create(data));
      this.cancelEdit();
    });
  }

  async archive(customer: Customer): Promise<void> {
    await this.run(async () => {
      await firstValueFrom(this.api.archive(customer.id));
      this.confirmingArchive.set(null);
    });
  }

  private async run(action: () => Promise<void>): Promise<void> {
    if (this.busy()) {
      return;
    }
    this.busy.set(true);
    this.problem.set(null);
    try {
      await action();
      this.customers.set(await firstValueFrom(this.api.list()));
    } catch (error) {
      this.problem.set(toApiProblem(error));
    } finally {
      this.busy.set(false);
    }
  }
}

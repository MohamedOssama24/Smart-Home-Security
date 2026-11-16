import { LocalizedDatePipe } from '../../core/i18n/localized-date.pipe';
import { ChangeDetectionStrategy, Component, OnInit, computed, inject, signal } from '@angular/core';
import { FormBuilder, FormGroup, ReactiveFormsModule, Validators } from '@angular/forms';
import { TranslocoPipe } from '@jsverse/transloco';
import { firstValueFrom } from 'rxjs';
import { ApiProblem, toApiProblem } from '../../core/api/api-error';
import { ScopeType, hasTenantWidePermission } from '../../core/auth/auth.models';
import { AuthService } from '../../core/auth/auth.service';
import { Customer, CustomersApi } from '../../core/customers/customers.api';
import { Home, HomesApi } from '../../core/homes/homes.api';
import { RoleDefinition, TenantUser, UserRoleAssignment, UsersApi } from '../../core/users/users.api';

/** Scopes the dashboard lets administrators grant (PLATFORM is never granted from a tenant). */
const GRANTABLE_SCOPES: readonly ScopeType[] = ['TENANT', 'CUSTOMER', 'HOME'];

/**
 * Users of the tenant: invitation by e-mail (the invited user chooses the password), enable /
 * disable with immediate effect, role assignments with their scope. The backend enforces
 * every rule (no escalation, last administrator, plan limit): the page only reflects them.
 */
@Component({
  selector: 'app-users-page',
  imports: [ReactiveFormsModule, TranslocoPipe, LocalizedDatePipe],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <section class="card wide">
      <h1>{{ 'users.title' | transloco }}</h1>
      @if (problem(); as p) {
        <div class="alert error" role="alert" data-testid="problem">{{ p.messageKey | transloco }}</div>
      }
      @if (notice(); as n) {
        <div class="alert success" role="status">{{ n | transloco }}</div>
      }
      <table class="list" data-testid="users">
        <thead>
          <tr>
            <th>{{ 'users.user' | transloco }}</th>
            <th>{{ 'users.roles' | transloco }}</th>
            <th>{{ 'users.status' | transloco }}</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          @for (user of users(); track user.id) {
            <tr [attr.data-user]="user.email">
              <td>
                {{ user.displayName }}<br /><span class="muted">{{ user.email }}</span>
                @if (user.lastLoginAt) {
                  <br /><span class="muted">{{ 'users.lastLogin' | transloco }} {{ user.lastLoginAt | appDate: 'short' }}</span>
                }
              </td>
              <td>
                @for (role of user.roles; track role.id) {
                  <div>
                    {{ 'roles.' + role.role | transloco }} · {{ scopeLabel(role) | transloco: { name: scopeName(role) } }}
                    @if (canManage() && user.status !== 'DISABLED') {
                      @if (confirmingRole() === role.id) {
                        <button type="button" class="danger" (click)="removeRole(user, role)" [disabled]="busy()"
                                data-testid="confirm-remove-role">
                          {{ 'users.removeRoleConfirm' | transloco }}
                        </button>
                        <button type="button" (click)="confirmingRole.set(null)">{{ 'common.cancel' | transloco }}</button>
                      } @else {
                        <button type="button" (click)="confirmingRole.set(role.id)" [disabled]="busy()"
                                [attr.aria-label]="'users.removeRole' | transloco" data-testid="remove-role">×</button>
                      }
                    }
                  </div>
                } @empty {
                  <span class="muted">{{ 'users.noRoles' | transloco }}</span>
                }
              </td>
              <td>
                <span class="badge" [class.ok]="user.status === 'ACTIVE'" [class.err]="user.status === 'DISABLED'">
                  {{ (user.invitationPending ? 'users.state.INVITED' : 'users.state.' + user.status) | transloco }}
                </span>
              </td>
              <td>
                @if (canManage()) {
                  <div class="actions">
                    @if (user.invitationPending && user.status !== 'DISABLED') {
                      <button type="button" (click)="resend(user)" [disabled]="busy()" data-testid="resend">
                        {{ 'users.resend' | transloco }}
                      </button>
                    }
                    @if (user.status !== 'DISABLED') {
                      <button type="button" (click)="selectForRole(user)" [disabled]="busy()">
                        {{ 'users.addRole' | transloco }}
                      </button>
                    }
                    @if (user.id !== me()?.id) {
                      @if (user.status === 'DISABLED') {
                        <button type="button" (click)="setStatus(user, 'ACTIVE')" [disabled]="busy()" data-testid="enable">
                          {{ 'users.enable' | transloco }}
                        </button>
                      } @else if (confirmingDisable() === user.id) {
                        <span class="muted" role="status">{{ 'users.disableConfirm' | transloco }}</span>
                        <button type="button" class="danger" (click)="setStatus(user, 'DISABLED')" [disabled]="busy()"
                                data-testid="confirm-disable">
                          {{ 'users.disableConfirmYes' | transloco }}
                        </button>
                        <button type="button" (click)="confirmingDisable.set(null)">{{ 'common.cancel' | transloco }}</button>
                      } @else {
                        <button type="button" class="danger" (click)="confirmingDisable.set(user.id)" [disabled]="busy()"
                                data-testid="disable">
                          {{ 'users.disable' | transloco }}
                        </button>
                      }
                    }
                  </div>
                }
              </td>
            </tr>
          }
        </tbody>
      </table>
    </section>

    @if (canManage()) {
      @if (roleTarget(); as target) {
        <section class="card wide" data-testid="add-role">
          <h2>{{ 'users.addRoleTitle' | transloco: { name: target.displayName } }}</h2>
          <form [formGroup]="roleForm" (ngSubmit)="addRole(target)" novalidate>
            <div class="field">
              <label for="roleRole">{{ 'users.role' | transloco }}</label>
              <select id="roleRole" formControlName="role">
                @for (role of roles(); track role.code) {
                  <option [value]="role.code">{{ 'roles.' + role.code | transloco }}</option>
                }
              </select>
            </div>
            <div class="field">
              <label for="roleScope">{{ 'users.scope' | transloco }}</label>
              <select id="roleScope" formControlName="scopeType">
                @for (scope of scopesFor(roleForm.controls.role.value); track scope) {
                  <option [value]="scope">{{ 'users.scopeType.' + scope | transloco }}</option>
                }
              </select>
            </div>
            @if (roleForm.controls.scopeType.value !== 'TENANT') {
              <div class="field">
                <label for="roleScopeId">{{ 'users.scopeTarget' | transloco }}</label>
                <select id="roleScopeId" formControlName="scopeId">
                  @for (option of targetsFor(roleForm.controls.scopeType.value); track option.id) {
                    <option [value]="option.id">{{ option.name }}</option>
                  }
                </select>
              </div>
            }
            <div class="actions">
              <button class="primary" type="submit" [disabled]="busy() || !scopeComplete(roleForm)">
                {{ 'users.addRole' | transloco }}
              </button>
              <button type="button" (click)="roleTarget.set(null)">{{ 'common.cancel' | transloco }}</button>
            </div>
          </form>
        </section>
      }

      <section class="card wide">
        <h2>{{ 'users.invite.title' | transloco }}</h2>
        <p class="muted">{{ 'users.invite.description' | transloco }}</p>
        <form [formGroup]="inviteForm" (ngSubmit)="invite()" novalidate>
          <div class="field">
            <label for="inviteEmail">{{ 'auth.fields.email' | transloco }}</label>
            <input id="inviteEmail" type="email" formControlName="email" autocomplete="off" />
          </div>
          <div class="field">
            <label for="inviteName">{{ 'auth.fields.displayName' | transloco }}</label>
            <input id="inviteName" formControlName="displayName" autocomplete="off" />
          </div>
          <div class="field">
            <label for="inviteLocale">{{ 'app.language' | transloco }}</label>
            <select id="inviteLocale" formControlName="locale">
              <option value="it">{{ 'app.languages.it' | transloco }}</option>
              <option value="en">{{ 'app.languages.en' | transloco }}</option>
            </select>
          </div>
          <div class="field">
            <label for="inviteRole">{{ 'users.role' | transloco }}</label>
            <select id="inviteRole" formControlName="role">
              @for (role of roles(); track role.code) {
                <option [value]="role.code">{{ 'roles.' + role.code | transloco }}</option>
              }
            </select>
          </div>
          <div class="field">
            <label for="inviteScope">{{ 'users.scope' | transloco }}</label>
            <select id="inviteScope" formControlName="scopeType">
              @for (scope of scopesFor(inviteForm.controls.role.value); track scope) {
                <option [value]="scope">{{ 'users.scopeType.' + scope | transloco }}</option>
              }
            </select>
          </div>
          @if (inviteForm.controls.scopeType.value !== 'TENANT') {
            <div class="field">
              <label for="inviteScopeId">{{ 'users.scopeTarget' | transloco }}</label>
              <select id="inviteScopeId" formControlName="scopeId">
                @for (option of targetsFor(inviteForm.controls.scopeType.value); track option.id) {
                  <option [value]="option.id">{{ option.name }}</option>
                }
              </select>
            </div>
          }
          <button class="primary" type="submit" [disabled]="busy() || inviteForm.invalid || !scopeComplete(inviteForm)">
            {{ 'users.invite.submit' | transloco }}
          </button>
        </form>
      </section>
    }
  `,
})
export class UsersPage implements OnInit {
  private readonly api = inject(UsersApi);
  private readonly homesApi = inject(HomesApi);
  private readonly customersApi = inject(CustomersApi);
  private readonly auth = inject(AuthService);
  private readonly fb = inject(FormBuilder).nonNullable;

  readonly me = this.auth.me;
  readonly users = signal<TenantUser[]>([]);
  readonly roles = signal<RoleDefinition[]>([]);
  readonly homes = signal<Home[]>([]);
  readonly customers = signal<Customer[]>([]);
  readonly busy = signal(false);
  readonly problem = signal<ApiProblem | null>(null);
  readonly notice = signal<string | null>(null);
  readonly confirmingDisable = signal<string | null>(null);
  readonly confirmingRole = signal<string | null>(null);
  readonly roleTarget = signal<TenantUser | null>(null);
  private readonly business = computed(() => this.me()?.tenant.type === 'BUSINESS');

  readonly inviteForm = this.fb.group({
    email: ['', [Validators.required, Validators.email, Validators.maxLength(254)]],
    displayName: ['', [Validators.required, Validators.maxLength(100)]],
    locale: ['it' as 'it' | 'en'],
    role: ['TECHNICIAN', [Validators.required]],
    scopeType: ['TENANT' as ScopeType, [Validators.required]],
    scopeId: [''],
  });

  readonly roleForm = this.fb.group({
    role: ['TECHNICIAN', [Validators.required]],
    scopeType: ['TENANT' as ScopeType, [Validators.required]],
    scopeId: [''],
  });

  constructor() {
    for (const form of [this.inviteForm, this.roleForm] as FormGroup[]) {
      // keep the scope consistent with the chosen role and the chosen target consistent with the scope
      form.get('role')!.valueChanges.subscribe((role: string) => {
        const scopes = this.scopesFor(role);
        if (!scopes.includes(form.get('scopeType')!.value)) {
          form.get('scopeType')!.setValue(scopes[0] ?? 'TENANT');
        }
      });
      form.get('scopeType')!.valueChanges.subscribe((scope: ScopeType) => {
        form.get('scopeId')!.setValue(this.targetsFor(scope)[0]?.id ?? '');
      });
    }
  }

  /** UI hint only: the backend decides (tenant-wide user:manage). */
  canManage(): boolean {
    return hasTenantWidePermission(this.me(), 'user:manage');
  }

  ngOnInit(): void {
    void this.load();
  }

  async load(): Promise<void> {
    try {
      this.users.set(await firstValueFrom(this.api.list()));
      if (this.canManage()) {
        this.roles.set(await firstValueFrom(this.api.roles()));
        this.homes.set(await firstValueFrom(this.homesApi.list()));
        if (this.business() && this.auth.hasPermission('customer:read')) {
          this.customers.set(await firstValueFrom(this.customersApi.list()));
        }
      }
    } catch (error) {
      this.problem.set(toApiProblem(error));
    }
  }

  scopesFor(roleCode: string): ScopeType[] {
    const role = this.roles().find((r) => r.code === roleCode);
    return GRANTABLE_SCOPES.filter(
      (s) => role?.assignableScopes.includes(s) && (s !== 'CUSTOMER' || this.business()),
    );
  }

  targetsFor(scope: ScopeType): { id: string; name: string }[] {
    if (scope === 'HOME') {
      return this.homes().map((h) => ({ id: h.id, name: h.name }));
    }
    if (scope === 'CUSTOMER') {
      return this.customers().map((c) => ({ id: c.id, name: c.displayName }));
    }
    return [];
  }

  scopeComplete(form: FormGroup): boolean {
    return form.get('scopeType')!.value === 'TENANT' || !!form.get('scopeId')!.value;
  }

  scopeLabel(role: UserRoleAssignment): string {
    return role.scopeId ? `users.scopeOf.${role.scopeType}` : `users.scopeType.${role.scopeType}`;
  }

  scopeName(role: UserRoleAssignment): string {
    const target = this.targetsFor(role.scopeType).find((t) => t.id === role.scopeId);
    return target?.name ?? '—';
  }

  async invite(): Promise<void> {
    if (this.inviteForm.invalid || !this.scopeComplete(this.inviteForm)) {
      return;
    }
    const value = this.inviteForm.getRawValue();
    await this.run(async () => {
      await firstValueFrom(
        this.api.invite({
          email: value.email.trim(),
          displayName: value.displayName.trim(),
          locale: value.locale,
          role: value.role,
          scopeType: value.scopeType,
          scopeId: value.scopeType === 'TENANT' ? null : value.scopeId,
        }),
      );
      this.inviteForm.reset();
      this.notice.set('users.invite.sent');
    });
  }

  async resend(user: TenantUser): Promise<void> {
    await this.run(async () => {
      await firstValueFrom(this.api.resendInvitation(user.id));
      this.notice.set('users.invite.resent');
    });
  }

  async setStatus(user: TenantUser, status: 'ACTIVE' | 'DISABLED'): Promise<void> {
    await this.run(async () => {
      await firstValueFrom(this.api.update(user.id, { status }));
      this.confirmingDisable.set(null);
    });
  }

  selectForRole(user: TenantUser): void {
    this.roleTarget.set(user);
    this.roleForm.reset();
  }

  async addRole(user: TenantUser): Promise<void> {
    if (!this.scopeComplete(this.roleForm)) {
      return;
    }
    const value = this.roleForm.getRawValue();
    await this.run(async () => {
      await firstValueFrom(
        this.api.assignRole(user.id, {
          role: value.role,
          scopeType: value.scopeType,
          scopeId: value.scopeType === 'TENANT' ? null : value.scopeId,
        }),
      );
      this.roleTarget.set(null);
    });
  }

  async removeRole(user: TenantUser, role: UserRoleAssignment): Promise<void> {
    await this.run(async () => {
      await firstValueFrom(this.api.removeRole(user.id, role.id));
      this.confirmingRole.set(null);
    });
  }

  private async run(action: () => Promise<void>): Promise<void> {
    if (this.busy()) {
      return;
    }
    this.busy.set(true);
    this.problem.set(null);
    this.notice.set(null);
    try {
      await action();
      this.users.set(await firstValueFrom(this.api.list()));
    } catch (error) {
      this.problem.set(toApiProblem(error));
    } finally {
      this.busy.set(false);
    }
  }
}

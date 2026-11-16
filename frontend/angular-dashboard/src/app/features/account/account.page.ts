import { LocalizedDatePipe } from '../../core/i18n/localized-date.pipe';
import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { Router } from '@angular/router';
import { TranslocoPipe } from '@jsverse/transloco';
import { firstValueFrom } from 'rxjs';
import { ApiProblem, toApiProblem } from '../../core/api/api-error';
import { AccountApi } from '../../core/auth/account.api';
import { PASSWORD_MAX_LENGTH, PASSWORD_MIN_LENGTH, UserSession } from '../../core/auth/auth.models';
import { AuthService } from '../../core/auth/auth.service';

@Component({
  selector: 'app-account-page',
  imports: [ReactiveFormsModule, TranslocoPipe, LocalizedDatePipe],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    @if (auth.me(); as me) {
      <section class="card wide">
        <h1>{{ 'account.title' | transloco }}</h1>
        <p class="muted">
          {{ me.displayName }} · {{ me.email }} · {{ me.tenant.name }}
        </p>
        <p>
          @for (role of me.roles; track role.id) {
            <span class="badge" style="margin-right: 6px">{{ 'roles.' + role.role | transloco }}</span>
          }
        </p>
      </section>
    }

    <section class="card wide">
      <h2>{{ 'account.password.title' | transloco }}</h2>
      @if (passwordProblem(); as p) {
        <div class="alert error" role="alert">
          {{ p.messageKey | transloco: { seconds: p.retryAfterSeconds } }}
          @if (p.violations.length) {
            <ul>
              @for (v of p.violations; track v) {
                <li>{{ 'auth.password.' + v | transloco }}</li>
              }
            </ul>
          }
        </div>
      }
      @if (passwordChanged()) {
        <div class="alert success" role="status">{{ 'account.password.done' | transloco }}</div>
      }
      <form [formGroup]="passwordForm" (ngSubmit)="changePassword()" novalidate>
        <div class="field">
          <label for="current">{{ 'account.password.current' | transloco }}</label>
          <input id="current" type="password" formControlName="current" autocomplete="current-password" />
        </div>
        <div class="field">
          <label for="next">{{ 'account.password.new' | transloco }}</label>
          <input id="next" type="password" formControlName="next" autocomplete="new-password" />
          <span class="hint">{{ 'auth.password.hint' | transloco: { min: minLength } }}</span>
        </div>
        <button class="primary" type="submit" [disabled]="busy() || passwordForm.invalid">
          {{ 'account.password.submit' | transloco }}
        </button>
      </form>
    </section>

    <section class="card wide">
      <h2>{{ 'account.sessions.title' | transloco }}</h2>
      <p class="muted">{{ 'account.sessions.description' | transloco }}</p>
      @if (sessionsProblem(); as p) {
        <div class="alert error" role="alert">{{ p.messageKey | transloco }}</div>
      }
      <table class="list" data-testid="sessions">
        <thead>
          <tr>
            <th>{{ 'account.sessions.device' | transloco }}</th>
            <th>{{ 'account.sessions.lastUsed' | transloco }}</th>
            <th>{{ 'account.sessions.ip' | transloco }}</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          @for (session of sessions(); track session.id) {
            <tr>
              <td>
                {{ session.deviceLabel ?? ('account.sessions.unknownDevice' | transloco) }}
                @if (session.current) {
                  <span class="badge ok">{{ 'account.sessions.current' | transloco }}</span>
                }
              </td>
              <td>{{ session.lastUsedAt | appDate: 'short' }}</td>
              <td>{{ session.ipAddress }}</td>
              <td>
                @if (!session.current) {
                  <button type="button" class="danger" (click)="revoke(session)" [disabled]="busy()">
                    {{ 'account.sessions.revoke' | transloco }}
                  </button>
                }
              </td>
            </tr>
          }
        </tbody>
      </table>
      <div class="actions" style="margin-top: 16px">
        <button type="button" (click)="revokeOthers()" [disabled]="busy()">
          {{ 'account.sessions.revokeOthers' | transloco }}
        </button>
        <button type="button" class="danger" (click)="revokeAll()" [disabled]="busy()" data-testid="revoke-all">
          {{ 'account.sessions.revokeAll' | transloco }}
        </button>
      </div>
    </section>
  `,
})
export class AccountPage implements OnInit {
  protected readonly auth = inject(AuthService);
  private readonly api = inject(AccountApi);
  private readonly router = inject(Router);

  readonly minLength = PASSWORD_MIN_LENGTH;
  readonly passwordForm = inject(FormBuilder).nonNullable.group({
    current: ['', Validators.required],
    next: ['', [Validators.required, Validators.minLength(PASSWORD_MIN_LENGTH), Validators.maxLength(PASSWORD_MAX_LENGTH)]],
  });
  readonly sessions = signal<UserSession[]>([]);
  readonly busy = signal(false);
  readonly passwordChanged = signal(false);
  readonly passwordProblem = signal<ApiProblem | null>(null);
  readonly sessionsProblem = signal<ApiProblem | null>(null);

  ngOnInit(): void {
    void this.loadSessions();
  }

  async loadSessions(): Promise<void> {
    try {
      this.sessions.set(await firstValueFrom(this.api.sessions()));
    } catch (error) {
      this.sessionsProblem.set(toApiProblem(error));
    }
  }

  async changePassword(): Promise<void> {
    if (this.passwordForm.invalid || this.busy()) {
      return;
    }
    this.busy.set(true);
    this.passwordProblem.set(null);
    this.passwordChanged.set(false);
    const { current, next } = this.passwordForm.getRawValue();
    try {
      await firstValueFrom(this.api.changePassword(current, next));
      this.passwordForm.reset();
      this.passwordChanged.set(true);
      await this.loadSessions();
    } catch (error) {
      this.passwordProblem.set(toApiProblem(error));
    } finally {
      this.busy.set(false);
    }
  }

  async revoke(session: UserSession): Promise<void> {
    await this.run(async () => {
      await firstValueFrom(this.api.revokeSession(session.id));
      await this.loadSessions();
    });
  }

  async revokeOthers(): Promise<void> {
    await this.run(async () => {
      await firstValueFrom(this.api.revokeAllSessions(false));
      await this.loadSessions();
    });
  }

  /** Signs out everywhere, including this browser. */
  async revokeAll(): Promise<void> {
    await this.run(async () => {
      await firstValueFrom(this.api.revokeAllSessions(true));
      this.auth.clear();
      await this.router.navigateByUrl('/login');
    });
  }

  private async run(action: () => Promise<void>): Promise<void> {
    this.busy.set(true);
    this.sessionsProblem.set(null);
    try {
      await action();
    } catch (error) {
      this.sessionsProblem.set(toApiProblem(error));
    } finally {
      this.busy.set(false);
    }
  }
}

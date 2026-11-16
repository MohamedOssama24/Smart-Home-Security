import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { TranslocoPipe } from '@jsverse/transloco';
import { ApiProblem, toApiProblem } from '../../core/api/api-error';
import { safeReturnUrl } from '../../core/auth/auth.guards';
import { AuthService } from '../../core/auth/auth.service';

@Component({
  selector: 'app-login-page',
  imports: [ReactiveFormsModule, RouterLink, TranslocoPipe],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <section class="card">
      <h1>{{ 'auth.login.title' | transloco }}</h1>
      @if (expired) {
        <div class="alert warning" role="status">{{ 'auth.login.expired' | transloco }}</div>
      }
      @if (problem(); as p) {
        <div class="alert error" role="alert" data-testid="login-error">
          {{ p.messageKey | transloco: { seconds: p.retryAfterSeconds } }}
          @if (p.code === 'EMAIL_NOT_VERIFIED') {
            <div class="actions" style="margin-top: 8px">
              <button type="button" (click)="resend()" [disabled]="busy()">
                {{ 'auth.verify.resend' | transloco }}
              </button>
            </div>
          }
        </div>
      }
      @if (resent()) {
        <div class="alert success" role="status">{{ 'auth.verify.resent' | transloco }}</div>
      }
      <form [formGroup]="form" (ngSubmit)="submit()" novalidate>
        <div class="field">
          <label for="email">{{ 'auth.fields.email' | transloco }}</label>
          <input id="email" type="email" formControlName="email" autocomplete="username" required />
        </div>
        <div class="field">
          <label for="password">{{ 'auth.fields.password' | transloco }}</label>
          <input id="password" type="password" formControlName="password" autocomplete="current-password" required />
        </div>
        <button class="primary" type="submit" [disabled]="busy() || form.invalid">
          {{ 'auth.login.submit' | transloco }}
        </button>
      </form>
      <div class="links">
        <a routerLink="/forgot-password">{{ 'auth.login.forgot' | transloco }}</a>
        <a routerLink="/register">{{ 'auth.login.register' | transloco }}</a>
      </div>
    </section>
  `,
})
export class LoginPage {
  private readonly auth = inject(AuthService);
  private readonly router = inject(Router);
  private readonly route = inject(ActivatedRoute);

  readonly form = inject(FormBuilder).nonNullable.group({
    email: ['', [Validators.required, Validators.email, Validators.maxLength(254)]],
    password: ['', [Validators.required, Validators.maxLength(1024)]],
  });
  readonly busy = signal(false);
  readonly problem = signal<ApiProblem | null>(null);
  readonly resent = signal(false);
  readonly expired = this.route.snapshot.queryParamMap.has('expired');

  async submit(): Promise<void> {
    if (this.form.invalid || this.busy()) {
      return;
    }
    this.busy.set(true);
    this.problem.set(null);
    this.resent.set(false);
    const { email, password } = this.form.getRawValue();
    try {
      await this.auth.login(email, password);
      await this.router.navigateByUrl(safeReturnUrl(this.route.snapshot.queryParamMap.get('returnUrl')));
    } catch (error) {
      this.problem.set(toApiProblem(error));
      this.form.controls.password.reset();
    } finally {
      this.busy.set(false);
    }
  }

  async resend(): Promise<void> {
    this.busy.set(true);
    try {
      await this.auth.resendVerification(this.form.controls.email.value);
      this.problem.set(null);
      this.resent.set(true);
    } catch (error) {
      this.problem.set(toApiProblem(error));
    } finally {
      this.busy.set(false);
    }
  }
}

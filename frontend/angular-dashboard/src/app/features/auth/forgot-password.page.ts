import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { TranslocoPipe } from '@jsverse/transloco';
import { ApiProblem, toApiProblem } from '../../core/api/api-error';
import { AuthService } from '../../core/auth/auth.service';

@Component({
  selector: 'app-forgot-password-page',
  imports: [ReactiveFormsModule, RouterLink, TranslocoPipe],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <section class="card">
      <h1>{{ 'auth.forgot.title' | transloco }}</h1>
      @if (sent()) {
        <!-- same message whether or not the address is registered -->
        <div class="alert success" role="status" data-testid="forgot-sent">{{ 'auth.forgot.sent' | transloco }}</div>
      } @else {
        <p class="muted">{{ 'auth.forgot.description' | transloco }}</p>
        @if (problem(); as p) {
          <div class="alert error" role="alert">{{ p.messageKey | transloco: { seconds: p.retryAfterSeconds } }}</div>
        }
        <form [formGroup]="form" (ngSubmit)="submit()" novalidate>
          <div class="field">
            <label for="email">{{ 'auth.fields.email' | transloco }}</label>
            <input id="email" type="email" formControlName="email" autocomplete="email" required />
          </div>
          <button class="primary" type="submit" [disabled]="busy() || form.invalid">
            {{ 'auth.forgot.submit' | transloco }}
          </button>
        </form>
      }
      <div class="links">
        <a routerLink="/login">{{ 'auth.register.toLogin' | transloco }}</a>
      </div>
    </section>
  `,
})
export class ForgotPasswordPage {
  private readonly auth = inject(AuthService);

  readonly form = inject(FormBuilder).nonNullable.group({
    email: ['', [Validators.required, Validators.email, Validators.maxLength(254)]],
  });
  readonly busy = signal(false);
  readonly sent = signal(false);
  readonly problem = signal<ApiProblem | null>(null);

  async submit(): Promise<void> {
    if (this.form.invalid || this.busy()) {
      return;
    }
    this.busy.set(true);
    this.problem.set(null);
    try {
      await this.auth.forgotPassword(this.form.controls.email.value.trim());
      this.sent.set(true);
    } catch (error) {
      this.problem.set(toApiProblem(error));
    } finally {
      this.busy.set(false);
    }
  }
}

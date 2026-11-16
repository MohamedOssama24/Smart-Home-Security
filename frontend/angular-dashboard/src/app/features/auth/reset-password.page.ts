import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { TranslocoPipe } from '@jsverse/transloco';
import { ApiProblem, toApiProblem } from '../../core/api/api-error';
import { PASSWORD_MAX_LENGTH, PASSWORD_MIN_LENGTH } from '../../core/auth/auth.models';
import { AuthService } from '../../core/auth/auth.service';
import { takeTokenFromFragment } from './token-from-fragment';

@Component({
  selector: 'app-reset-password-page',
  imports: [ReactiveFormsModule, RouterLink, TranslocoPipe],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <section class="card">
      <h1>{{ 'auth.reset.title' | transloco }}</h1>
      @if (!token) {
        <div class="alert error" role="alert">{{ 'errors.INVALID_TOKEN' | transloco }}</div>
      } @else if (done()) {
        <div class="alert success" role="status" data-testid="reset-done">{{ 'auth.reset.done' | transloco }}</div>
      } @else {
        @if (problem(); as p) {
          <div class="alert error" role="alert">
            {{ p.messageKey | transloco }}
            @if (p.violations.length) {
              <ul>
                @for (v of p.violations; track v) {
                  <li>{{ 'auth.password.' + v | transloco }}</li>
                }
              </ul>
            }
          </div>
        }
        <form [formGroup]="form" (ngSubmit)="submit()" novalidate>
          <div class="field">
            <label for="password">{{ 'auth.reset.newPassword' | transloco }}</label>
            <input id="password" type="password" formControlName="password" autocomplete="new-password" required />
            <span class="hint">{{ 'auth.password.hint' | transloco: { min: minLength } }}</span>
          </div>
          <button class="primary" type="submit" [disabled]="busy() || form.invalid">
            {{ 'auth.reset.submit' | transloco }}
          </button>
        </form>
      }
      <div class="links">
        <a routerLink="/login">{{ 'auth.register.toLogin' | transloco }}</a>
      </div>
    </section>
  `,
})
export class ResetPasswordPage {
  private readonly auth = inject(AuthService);

  readonly token = takeTokenFromFragment(inject(ActivatedRoute).snapshot.fragment);
  readonly minLength = PASSWORD_MIN_LENGTH;
  readonly form = inject(FormBuilder).nonNullable.group({
    password: [
      '',
      [Validators.required, Validators.minLength(PASSWORD_MIN_LENGTH), Validators.maxLength(PASSWORD_MAX_LENGTH)],
    ],
  });
  readonly busy = signal(false);
  readonly done = signal(false);
  readonly problem = signal<ApiProblem | null>(null);

  async submit(): Promise<void> {
    if (!this.token || this.form.invalid || this.busy()) {
      return;
    }
    this.busy.set(true);
    this.problem.set(null);
    try {
      await this.auth.resetPassword(this.token, this.form.controls.password.value);
      this.done.set(true);
    } catch (error) {
      this.problem.set(toApiProblem(error));
    } finally {
      this.busy.set(false);
    }
  }
}

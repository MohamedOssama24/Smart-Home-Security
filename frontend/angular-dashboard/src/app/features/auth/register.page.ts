import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { TranslocoPipe } from '@jsverse/transloco';
import { ApiProblem, toApiProblem } from '../../core/api/api-error';
import { AccountType, PASSWORD_MAX_LENGTH, PASSWORD_MIN_LENGTH } from '../../core/auth/auth.models';
import { AuthService } from '../../core/auth/auth.service';
import { LanguageService } from '../../core/i18n/language.service';

@Component({
  selector: 'app-register-page',
  imports: [ReactiveFormsModule, RouterLink, TranslocoPipe],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <section class="card">
      <h1>{{ 'auth.register.title' | transloco }}</h1>
      @if (done()) {
        <div class="alert success" role="status" data-testid="register-done">
          {{ 'auth.register.done' | transloco }}
        </div>
        <a routerLink="/login">{{ 'auth.register.toLogin' | transloco }}</a>
      } @else {
        @if (problem(); as p) {
          <div class="alert error" role="alert" data-testid="register-error">
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
        <form [formGroup]="form" (ngSubmit)="submit()" novalidate>
          <div class="field">
            <label for="accountType">{{ 'auth.register.accountType' | transloco }}</label>
            <select id="accountType" formControlName="accountType">
              <option value="INDIVIDUAL">{{ 'auth.register.individual' | transloco }}</option>
              <option value="BUSINESS">{{ 'auth.register.business' | transloco }}</option>
            </select>
          </div>
          @if (form.controls.accountType.value === 'BUSINESS') {
            <div class="field">
              <label for="organizationName">{{ 'auth.fields.organization' | transloco }}</label>
              <input id="organizationName" formControlName="organizationName" autocomplete="organization" />
            </div>
          }
          <div class="field">
            <label for="displayName">{{ 'auth.fields.displayName' | transloco }}</label>
            <input id="displayName" formControlName="displayName" autocomplete="name" required />
          </div>
          <div class="field">
            <label for="email">{{ 'auth.fields.email' | transloco }}</label>
            <input id="email" type="email" formControlName="email" autocomplete="email" required />
          </div>
          <div class="field">
            <label for="password">{{ 'auth.fields.password' | transloco }}</label>
            <input id="password" type="password" formControlName="password" autocomplete="new-password" required />
            <span class="hint">{{ 'auth.password.hint' | transloco: { min: minLength } }}</span>
            @if (form.controls.password.touched && form.controls.password.errors?.['minlength']) {
              <span class="invalid" data-testid="password-too-short">
                {{ 'auth.password.PASSWORD_TOO_SHORT' | transloco }}
              </span>
            }
          </div>
          <button class="primary" type="submit" [disabled]="busy() || form.invalid">
            {{ 'auth.register.submit' | transloco }}
          </button>
        </form>
        <div class="links">
          <a routerLink="/login">{{ 'auth.register.haveAccount' | transloco }}</a>
        </div>
      }
    </section>
  `,
})
export class RegisterPage {
  private readonly auth = inject(AuthService);
  private readonly language = inject(LanguageService);

  readonly minLength = PASSWORD_MIN_LENGTH;
  readonly form = inject(FormBuilder).nonNullable.group({
    accountType: ['INDIVIDUAL' as AccountType, Validators.required],
    organizationName: ['', Validators.maxLength(200)],
    displayName: ['', [Validators.required, Validators.maxLength(100)]],
    email: ['', [Validators.required, Validators.email, Validators.maxLength(254)]],
    password: [
      '',
      [Validators.required, Validators.minLength(PASSWORD_MIN_LENGTH), Validators.maxLength(PASSWORD_MAX_LENGTH)],
    ],
  });
  readonly busy = signal(false);
  readonly done = signal(false);
  readonly problem = signal<ApiProblem | null>(null);

  async submit(): Promise<void> {
    if (this.form.invalid || this.busy()) {
      this.form.markAllAsTouched();
      return;
    }
    this.busy.set(true);
    this.problem.set(null);
    const value = this.form.getRawValue();
    try {
      await this.auth.register({
        email: value.email.trim(),
        password: value.password,
        displayName: value.displayName.trim(),
        locale: this.language.current(),
        accountType: value.accountType,
        organizationName: value.accountType === 'BUSINESS' ? value.organizationName.trim() : undefined,
      });
      this.done.set(true);
    } catch (error) {
      this.problem.set(toApiProblem(error));
    } finally {
      this.busy.set(false);
    }
  }
}

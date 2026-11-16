import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { TranslocoPipe } from '@jsverse/transloco';
import { ApiProblem, toApiProblem } from '../../core/api/api-error';
import { AuthService } from '../../core/auth/auth.service';
import { takeTokenFromFragment } from './token-from-fragment';

@Component({
  selector: 'app-verify-email-page',
  imports: [RouterLink, TranslocoPipe],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <section class="card" aria-live="polite">
      <h1>{{ 'auth.verify.title' | transloco }}</h1>
      @switch (state()) {
        @case ('working') {
          <p class="muted">{{ 'auth.verify.working' | transloco }}</p>
        }
        @case ('done') {
          <div class="alert success" data-testid="verify-done">{{ 'auth.verify.done' | transloco }}</div>
          <a routerLink="/login">{{ 'auth.register.toLogin' | transloco }}</a>
        }
        @default {
          <div class="alert error" data-testid="verify-error">
            {{ (problem()?.messageKey ?? 'errors.INVALID_TOKEN') | transloco }}
          </div>
          <a routerLink="/login">{{ 'auth.register.toLogin' | transloco }}</a>
        }
      }
    </section>
  `,
})
export class VerifyEmailPage implements OnInit {
  private readonly auth = inject(AuthService);
  private readonly route = inject(ActivatedRoute);

  readonly state = signal<'working' | 'done' | 'failed'>('working');
  readonly problem = signal<ApiProblem | null>(null);

  async ngOnInit(): Promise<void> {
    const token = takeTokenFromFragment(this.route.snapshot.fragment);
    if (!token) {
      this.state.set('failed');
      return;
    }
    try {
      await this.auth.verifyEmail(token);
      this.state.set('done');
    } catch (error) {
      this.problem.set(toApiProblem(error));
      this.state.set('failed');
    }
  }
}

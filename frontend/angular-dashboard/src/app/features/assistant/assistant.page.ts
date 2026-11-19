import { ChangeDetectionStrategy, Component, inject, input, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { TranslocoPipe, TranslocoService } from '@jsverse/transloco';
import { firstValueFrom } from 'rxjs';
import { ApiProblem, toApiProblem } from '../../core/api/api-error';
import { AssistantAnswer, AssistantApi } from '../../core/assistant/assistant.api';
import { LanguageService } from '../../core/i18n/language.service';
import { LocalizedDatePipe } from '../../core/i18n/localized-date.pipe';

const MAX_QUESTION = 500;

/**
 * AI security assistant of the home (Milestone 16): answers questions only with the data of the
 * home (score, findings, devices), cites them and performs no action. Nothing is stored: the
 * last answer lives only in this page.
 */
@Component({
  selector: 'app-assistant-page',
  imports: [RouterLink, TranslocoPipe, LocalizedDatePipe],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <p><a [routerLink]="['/homes', homeId()]">← {{ 'risk.backToHome' | transloco }}</a></p>
    <section class="card wide">
      <h1>{{ 'assistant.title' | transloco }}</h1>
      <p class="muted" data-testid="disclaimer">{{ 'assistant.disclaimer' | transloco }}</p>
      <form (submit)="$event.preventDefault(); ask()" data-testid="form">
        <label>{{ 'assistant.question' | transloco }}
          <textarea rows="3" [maxLength]="max" [value]="question()" (input)="question.set($any($event.target).value)"
                    [placeholder]="'assistant.placeholder' | transloco" data-testid="question"></textarea>
        </label>
        <div class="actions">
          @for (s of suggestions; track s) {
            <button type="button" (click)="suggest(s)" [disabled]="busy()">{{ s | transloco }}</button>
          }
          <button type="submit" class="primary" [disabled]="busy() || !question().trim()" data-testid="ask">{{ 'assistant.ask' | transloco }}</button>
        </div>
      </form>
      @if (problem(); as p) {
        <div class="alert error" role="alert" data-testid="problem">{{ p.messageKey | transloco }}</div>
      }
      @if (answer(); as a) {
        <article data-testid="answer">
          <p style="white-space: pre-line">{{ a.answer }}</p>
          @if (a.citations.length) {
            <p class="small">{{ 'assistant.sources' | transloco }}
              @for (c of a.citations; track c.id) {
                <span class="badge" [class.err]="c.severity === 'CRITICAL' || c.severity === 'HIGH'"
                      [attr.data-testid]="'citation-' + c.id">{{ c.id }} · {{ 'assistant.kind.' + c.kind | transloco }}: {{ c.label }}</span>
              }
            </p>
          }
          <p class="small muted" data-testid="meta">
            {{ 'assistant.provider' | transloco: { provider: a.provider } }}
            @if (a.fallback) {
              · <span data-testid="fallback">{{ 'assistant.fallback.' + a.fallbackReason | transloco }}</span>
            }
            @if (a.dataAsOf) {
              · {{ 'assistant.dataAsOf' | transloco }} {{ a.dataAsOf | appDate: 'short' }}
            }
          </p>
        </article>
      }
    </section>
  `,
})
export class AssistantPage {
  /** Route parameter (component input binding). */
  readonly homeId = input.required<string>({ alias: 'id' });
  private readonly api = inject(AssistantApi);
  private readonly language = inject(LanguageService);
  private readonly transloco = inject(TranslocoService);

  protected readonly max = MAX_QUESTION;
  protected readonly suggestions = ['assistant.suggest.risk', 'assistant.suggest.fix', 'assistant.suggest.devices'];
  readonly question = signal('');
  readonly answer = signal<AssistantAnswer | null>(null);
  readonly problem = signal<ApiProblem | null>(null);
  readonly busy = signal(false);

  protected suggest(key: string): void {
    this.question.set(this.transloco.translate(key));
    void this.ask();
  }

  async ask(): Promise<void> {
    const question = this.question().trim();
    if (!question || this.busy()) {
      return;
    }
    this.busy.set(true);
    this.problem.set(null);
    try {
      const locale = this.language.current() === 'en' ? 'en' : 'it';
      this.answer.set(await firstValueFrom(this.api.ask(this.homeId(), question.slice(0, MAX_QUESTION), locale)));
    } catch (e) {
      this.answer.set(null);
      this.problem.set(toApiProblem(e));
    } finally {
      this.busy.set(false);
    }
  }
}

import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { TranslocoPipe } from '@jsverse/transloco';
import { firstValueFrom } from 'rxjs';
import { ApiProblem, toApiProblem } from '../../core/api/api-error';
import { Alert, AlertsApi, UnreadAlerts } from '../../core/alerts/alerts.api';
import { LocalizedDatePipe } from '../../core/i18n/localized-date.pipe';

/** Page of the home the alert is about. */
const TARGET: Record<Alert['type'], string | null> = {
  NEW_FINDING: 'findings',
  FINDING_RESOLVED: 'findings',
  SCORE_DROPPED: 'risk',
  NEW_DEVICE: 'devices',
  SCAN_FAILED: 'scans',
  AGENT_OFFLINE: null,
};

/**
 * Alerts of the user (Milestone 13): new HIGH/CRITICAL findings, resolved findings, score
 * drops, new devices, failed scans, agents offline. The same event repeated while the alert is
 * unresolved shows as one alert with its occurrences (deduplication).
 */
@Component({
  selector: 'app-alerts-page',
  imports: [RouterLink, TranslocoPipe, LocalizedDatePipe],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <section class="card wide">
      <h1>{{ 'alerts.title' | transloco }}</h1>
      <p class="muted">{{ 'alerts.description' | transloco }}</p>
      <div class="actions">
        <label><input type="checkbox" [checked]="unreadOnly()" (change)="toggleUnread($any($event.target).checked)"
                      data-testid="unread-only" /> {{ 'alerts.unreadOnly' | transloco }}</label>
        <button type="button" (click)="readAll()" [disabled]="busy()" data-testid="read-all">{{ 'alerts.readAll' | transloco }}</button>
        <a routerLink="/alerts/preferences" data-testid="preferences-link">{{ 'alerts.preferences.title' | transloco }} →</a>
      </div>
      @if (problem(); as p) {
        <div class="alert error" role="alert">{{ p.messageKey | transloco }}</div>
      }
      @if (alerts(); as list) {
        @if (list.length === 0) {
          <p class="muted" data-testid="no-alerts">{{ 'alerts.none' | transloco }}</p>
        }
        <ul class="alert-list" data-testid="alerts">
          @for (a of list; track a.id) {
            <li [class.unread]="!a.readAt" [attr.data-testid]="'alert-' + a.id">
              <div class="alert-head">
                <span class="badge" [class.err]="a.severity === 'CRITICAL' || a.severity === 'HIGH'"
                      [class.warn]="a.severity === 'MEDIUM'" [class.ok]="a.severity === 'INFO'">{{ 'alerts.severity.' + a.severity | transloco }}</span>
                <strong data-testid="alert-title">
                  @switch (a.type) {
                    @case ('NEW_FINDING') {
                      {{ 'alerts.text.NEW_FINDING' | transloco: { title: (a.payload['titleKey'] | transloco: a.payload['params']) } }}
                    }
                    @case ('FINDING_RESOLVED') {
                      {{ 'alerts.text.FINDING_RESOLVED' | transloco: { title: (a.payload['titleKey'] | transloco: a.payload['params']) } }}
                    }
                    @case ('SCORE_DROPPED') {
                      {{ 'alerts.text.SCORE_DROPPED' | transloco: { score: a.payload['score'], change: a.payload['scoreChange'] } }}
                    }
                    @case ('NEW_DEVICE') {
                      @if (a.payload['count'] > 1) {
                        {{ 'alerts.text.NEW_DEVICES' | transloco: { count: a.payload['count'] } }}
                      } @else {
                        {{ 'alerts.text.NEW_DEVICE' | transloco: { name: a.payload['devices'][0]?.name } }}
                      }
                    }
                    @case ('SCAN_FAILED') {
                      {{ 'alerts.text.SCAN_FAILED' | transloco: { reason: a.payload['reason'] } }}
                    }
                    @case ('AGENT_OFFLINE') {
                      {{ 'alerts.text.AGENT_OFFLINE' | transloco: { name: a.payload['agentName'] } }}
                    }
                  }
                </strong>
              </div>
              <div class="small muted">
                {{ a.homeName }}
                @if (a.payload['deviceName']) { · {{ a.payload['deviceName'] }} ({{ a.payload['deviceIp'] }}) }
                · {{ a.lastAt | appDate: 'short' }}
                @if (a.occurrences > 1) {
                  · <span data-testid="occurrences">{{ 'alerts.occurrences' | transloco: { count: a.occurrences } }}</span>
                }
                @if (a.resolvedAt) {
                  · <span class="badge ok" data-testid="resolved">{{ 'alerts.resolved' | transloco }}</span>
                }
              </div>
              <div class="actions">
                <a [routerLink]="link(a)">{{ 'alerts.open' | transloco }} →</a>
                @if (!a.readAt) {
                  <button type="button" class="link" (click)="read(a)" [disabled]="busy()" data-testid="read">{{ 'alerts.markRead' | transloco }}</button>
                }
              </div>
            </li>
          }
        </ul>
      }
    </section>
  `,
  styles: `
    .alert-list { list-style: none; padding: 0; margin: 0; }
    .alert-list li { border-top: 1px solid var(--border); padding: 0.75rem 0; }
    .alert-list li.unread { border-left: 4px solid var(--primary); padding-left: 0.75rem; }
    .alert-head { display: flex; gap: 0.5rem; align-items: baseline; flex-wrap: wrap; }
    button.link { background: none; border: none; padding: 0; color: inherit; text-decoration: underline; cursor: pointer; }
  `,
})
export class AlertsPage implements OnInit {
  private readonly api = inject(AlertsApi);
  private readonly unread = inject(UnreadAlerts);

  readonly alerts = signal<Alert[] | null>(null);
  readonly unreadOnly = signal(false);
  readonly problem = signal<ApiProblem | null>(null);
  readonly busy = signal(false);

  async ngOnInit(): Promise<void> {
    await this.load();
  }

  protected async toggleUnread(value: boolean): Promise<void> {
    this.unreadOnly.set(value);
    await this.load();
  }

  protected link(a: Alert): string[] {
    const target = TARGET[a.type];
    return target ? ['/homes', a.homeId, target] : ['/homes', a.homeId];
  }

  protected async read(a: Alert): Promise<void> {
    await this.run(async () => {
      await firstValueFrom(this.api.markRead(a.id));
      this.alerts.update((list) => (list ?? []).map((x) => (x.id === a.id ? { ...x, readAt: new Date().toISOString() } : x)));
    });
  }

  protected async readAll(): Promise<void> {
    await this.run(async () => {
      await firstValueFrom(this.api.markAllRead());
      await this.load();
    });
  }

  private async load(): Promise<void> {
    try {
      this.alerts.set(await firstValueFrom(this.api.list(this.unreadOnly())));
      this.problem.set(null);
    } catch (e) {
      this.problem.set(toApiProblem(e));
    }
  }

  private async run(action: () => Promise<void>): Promise<void> {
    this.busy.set(true);
    try {
      await action();
    } catch (e) {
      this.problem.set(toApiProblem(e));
    } finally {
      this.busy.set(false);
      this.unread.refresh();
    }
  }
}

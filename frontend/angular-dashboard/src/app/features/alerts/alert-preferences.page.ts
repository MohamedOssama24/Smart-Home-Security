import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { TranslocoPipe } from '@jsverse/transloco';
import { firstValueFrom } from 'rxjs';
import { ApiProblem, toApiProblem } from '../../core/api/api-error';
import {
  ALERT_SEVERITIES,
  ALERT_TYPES,
  AlertChannel,
  AlertSeverity,
  AlertType,
  AlertsApi,
  NotificationPreference,
} from '../../core/alerts/alerts.api';

/**
 * Notification preferences of the user (Milestone 13): for every alert type and channel
 * (dashboard, e-mail) on/off and the minimum severity. Defaults: everything on the dashboard,
 * e-mail from MEDIUM up.
 */
@Component({
  selector: 'app-alert-preferences-page',
  imports: [RouterLink, TranslocoPipe],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <p><a routerLink="/alerts">← {{ 'alerts.title' | transloco }}</a></p>
    <section class="card wide">
      <h1>{{ 'alerts.preferences.title' | transloco }}</h1>
      <p class="muted">{{ 'alerts.preferences.description' | transloco }}</p>
      @if (problem(); as p) {
        <div class="alert error" role="alert">{{ p.messageKey | transloco }}</div>
      }
      @if (saved()) {
        <div class="alert success" role="status" data-testid="saved">{{ 'alerts.preferences.saved' | transloco }}</div>
      }
      @if (items(); as list) {
        <table class="list" data-testid="preferences">
          <thead>
            <tr>
              <th>{{ 'alerts.preferences.type' | transloco }}</th>
              @for (c of channels; track c) {
                <th>{{ 'alerts.channel.' + c | transloco }}</th>
              }
            </tr>
          </thead>
          <tbody>
            @for (t of types; track t) {
              <tr [attr.data-testid]="'pref-' + t">
                <td>{{ 'alerts.type.' + t | transloco }}</td>
                @for (c of channels; track c) {
                  @if (find(list, t, c); as p) {
                    <td>
                      <label><input type="checkbox" [checked]="p.enabled" (change)="change(t, c, { enabled: $any($event.target).checked })"
                                    [attr.data-testid]="t + '-' + c + '-enabled'" /> {{ 'alerts.preferences.enabled' | transloco }}</label>
                      <label class="small">{{ 'alerts.preferences.minSeverity' | transloco }}
                        <select [value]="p.minSeverity" [disabled]="!p.enabled"
                                (change)="change(t, c, { minSeverity: $any($event.target).value })"
                                [attr.data-testid]="t + '-' + c + '-min'">
                          @for (s of severities; track s) {
                            <option [value]="s" [selected]="s === p.minSeverity">{{ 'alerts.severity.' + s | transloco }}</option>
                          }
                        </select>
                      </label>
                    </td>
                  }
                }
              </tr>
            }
          </tbody>
        </table>
        <p class="muted small">{{ 'alerts.preferences.note' | transloco }}</p>
        <button type="button" class="primary" (click)="save()" [disabled]="busy()" data-testid="save">{{ 'common.save' | transloco }}</button>
      }
    </section>
  `,
})
export class AlertPreferencesPage implements OnInit {
  private readonly api = inject(AlertsApi);
  protected readonly types = ALERT_TYPES;
  protected readonly channels: AlertChannel[] = ['DASHBOARD', 'EMAIL'];
  protected readonly severities = ALERT_SEVERITIES;

  readonly items = signal<NotificationPreference[] | null>(null);
  readonly problem = signal<ApiProblem | null>(null);
  readonly busy = signal(false);
  readonly saved = signal(false);

  async ngOnInit(): Promise<void> {
    try {
      this.items.set(await firstValueFrom(this.api.preferences()));
    } catch (e) {
      this.problem.set(toApiProblem(e));
    }
  }

  protected find(list: NotificationPreference[], type: AlertType, channel: AlertChannel): NotificationPreference | undefined {
    return list.find((p) => p.type === type && p.channel === channel);
  }

  protected change(type: AlertType, channel: AlertChannel, patch: { enabled?: boolean; minSeverity?: AlertSeverity }): void {
    this.saved.set(false);
    this.items.update((list) =>
      (list ?? []).map((p) => (p.type === type && p.channel === channel ? { ...p, ...patch } : p)),
    );
  }

  protected async save(): Promise<void> {
    this.busy.set(true);
    this.problem.set(null);
    try {
      this.items.set(await firstValueFrom(this.api.savePreferences(this.items() ?? [])));
      this.saved.set(true);
    } catch (e) {
      this.problem.set(toApiProblem(e));
    } finally {
      this.busy.set(false);
    }
  }
}

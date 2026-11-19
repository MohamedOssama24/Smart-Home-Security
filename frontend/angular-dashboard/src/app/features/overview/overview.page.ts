import { ChangeDetectionStrategy, Component, OnInit, computed, inject, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { TranslocoPipe } from '@jsverse/transloco';
import { firstValueFrom } from 'rxjs';
import { ApiProblem, toApiProblem } from '../../core/api/api-error';
import { LocalizedDatePipe } from '../../core/i18n/localized-date.pipe';
import { HomeOverview, OverviewApi } from '../../core/overview/overview.api';

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const;

/**
 * Dashboard overview (Milestone 12): every home with its last security score, coverage,
 * counted findings and last scan, the riskiest first. A home whose findings the user cannot
 * read is listed by name only.
 */
@Component({
  selector: 'app-overview-page',
  imports: [RouterLink, TranslocoPipe, LocalizedDatePipe],
  changeDetection: ChangeDetectionStrategy.OnPush,
  styles: [`
    .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; }
    .summary div { border: 1px solid var(--border); border-radius: 8px; padding: 10px; }
    .summary strong { display: block; font-size: 1.6rem; }
    .homes { display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap: 16px;
      max-width: 880px; margin: 0 auto; }
    .homes .card { margin: 0; max-width: none; padding: 16px; }
    .score { font-size: 2rem; font-weight: 700; }
    .counts { display: flex; gap: 6px; flex-wrap: wrap; margin: 8px 0; }
  `],
  template: `
    <section class="card wide">
      <h1>{{ 'overview.title' | transloco }}</h1>
      <p class="muted">{{ 'overview.description' | transloco }}</p>
      @if (problem(); as p) {
        <div class="alert error" role="alert">{{ p.messageKey | transloco }}</div>
      }
      @if (homes(); as list) {
        @if (list.length === 0) {
          <p class="muted" data-testid="no-homes">{{ 'overview.noHomes' | transloco }} <a routerLink="/homes">{{ 'overview.toHomes' | transloco }}</a></p>
        } @else {
          <div class="summary" data-testid="summary">
            <div><strong>{{ list.length }}</strong>{{ 'overview.summary.homes' | transloco }}</div>
            <div><strong>{{ summary().atRisk }}</strong>{{ 'overview.summary.atRisk' | transloco }}</div>
            <div><strong>{{ summary().critical }}</strong>{{ 'overview.summary.critical' | transloco }}</div>
            <div><strong>{{ summary().kev }}</strong>{{ 'overview.summary.kev' | transloco }}</div>
            <div><strong>{{ summary().unscored }}</strong>{{ 'overview.summary.unscored' | transloco }}</div>
          </div>
        }
      }
    </section>

    @if (sorted().length) {
      <div class="homes" data-testid="homes">
        @for (h of sorted(); track h.homeId) {
          <article class="card" [attr.data-testid]="'home-' + h.homeId">
            <h2><a [routerLink]="['/homes', h.homeId]">{{ h.name }}</a></h2>
            @if (h.security; as s) {
              @if (s.score !== null) {
                <div>
                  <span class="score" data-testid="score">{{ s.score }}</span><span class="muted">/100</span>
                  <span class="badge" [class.err]="s.riskLevel === 'HIGH' || s.riskLevel === 'CRITICAL'"
                        [class.warn]="s.riskLevel === 'MEDIUM'" [class.ok]="s.riskLevel === 'LOW'">
                    {{ 'risk.level.' + s.riskLevel | transloco }}</span>
                </div>
                <p class="small">
                  {{ 'risk.rating.' + s.rating | transloco }}
                  · {{ 'risk.coverage.title' | transloco }} {{ percent(s.coverage) }}
                  @if (s.scoreChange !== null && s.scoreChange !== 0) {
                    · <span data-testid="change">{{ signed(s.scoreChange) }}</span>
                  }
                </p>
                @if (s.provisional) {
                  <p class="badge warn" data-testid="provisional">{{ 'overview.provisional' | transloco }}</p>
                }
              } @else {
                <p class="muted" data-testid="no-score">{{ 'overview.noScore' | transloco }}</p>
              }
              @if (s.notComputedReason) {
                <p class="small muted" data-testid="not-computed">{{ 'overview.notComputed' | transloco }}</p>
              }
              <div class="counts" data-testid="findings">
                @for (sev of severities; track sev) {
                  @if (s.openFindings[sev]) {
                    <span class="badge" [class.err]="sev === 'CRITICAL' || sev === 'HIGH'" [class.warn]="sev === 'MEDIUM'">
                      {{ s.openFindings[sev] }} {{ 'findings.severity.' + sev | transloco }}</span>
                  }
                }
                @if (s.kevFindings) {
                  <span class="badge err" data-testid="kev">{{ s.kevFindings }} KEV</span>
                }
                @if (!countedTotal(h)) {
                  <span class="muted small">{{ 'overview.noFindings' | transloco }}</span>
                }
              </div>
              <p class="small muted">
                {{ 'overview.devices' | transloco: { count: s.devices } }} ·
                @if (s.lastScanAt) {
                  {{ 'overview.lastScan' | transloco }}: {{ s.lastScanAt | appDate: 'short' }}
                } @else {
                  {{ 'overview.neverScanned' | transloco }}
                }
              </p>
              <p class="actions small">
                <a [routerLink]="['/homes', h.homeId, 'risk']">{{ 'risk.title' | transloco }}</a>
                <a [routerLink]="['/homes', h.homeId, 'findings']">{{ 'findings.title' | transloco }}</a>
                <a [routerLink]="['/homes', h.homeId, 'network-map']">{{ 'networkMap.title' | transloco }}</a>
              </p>
            } @else {
              <p class="muted small" data-testid="restricted">{{ 'overview.restricted' | transloco }}</p>
            }
          </article>
        }
      </div>
    }
  `,
})
export class OverviewPage implements OnInit {
  private readonly api = inject(OverviewApi);
  protected readonly severities = SEVERITIES;
  readonly homes = signal<HomeOverview[] | null>(null);
  readonly problem = signal<ApiProblem | null>(null);

  /** Riskiest first: lowest score, then homes without a score, then homes without data. */
  readonly sorted = computed(() =>
    [...(this.homes() ?? [])].sort((a, b) => rank(a) - rank(b) || a.name.localeCompare(b.name)),
  );

  readonly summary = computed(() => {
    const list = this.homes() ?? [];
    const sec = list.map((h) => h.security).filter((s) => s !== null);
    return {
      atRisk: sec.filter((s) => s.riskLevel === 'HIGH' || s.riskLevel === 'CRITICAL').length,
      critical: sec.reduce((n, s) => n + (s.openFindings.CRITICAL ?? 0) + (s.openFindings.HIGH ?? 0), 0),
      kev: sec.reduce((n, s) => n + s.kevFindings, 0),
      unscored: sec.filter((s) => s.score === null).length,
    };
  });

  async ngOnInit(): Promise<void> {
    try {
      this.homes.set(await firstValueFrom(this.api.list()));
    } catch (e) {
      this.problem.set(toApiProblem(e));
    }
  }

  protected percent(value: number | null): string {
    return value === null ? '—' : `${Math.round(value * 100)}%`;
  }

  protected signed(value: number): string {
    return value > 0 ? `+${value}` : `${value}`;
  }

  protected countedTotal(h: HomeOverview): number {
    return Object.values(h.security?.openFindings ?? {}).reduce((n, v) => n + (v ?? 0), 0);
  }
}

function rank(h: HomeOverview): number {
  if (!h.security) {
    return 300;
  }
  return h.security.score ?? 200;
}

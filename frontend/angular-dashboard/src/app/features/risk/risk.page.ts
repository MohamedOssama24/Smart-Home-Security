import { ChangeDetectionStrategy, Component, OnInit, computed, inject, input, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { TranslocoPipe } from '@jsverse/transloco';
import { firstValueFrom } from 'rxjs';
import { ApiProblem, toApiProblem } from '../../core/api/api-error';
import { LocalizedDatePipe } from '../../core/i18n/localized-date.pipe';
import { RiskApi, RiskDeduction, RiskHistoryEntry, RiskOverview, RiskSnapshot } from '../../core/risk/risk.api';

/**
 * Security score of a home (Milestone 11): score, risk level and judgement, how much the scan
 * could look at (coverage), every deduction with its factors ("why this score?"), the riskiest
 * devices, what changed since the previous score, and the history. A low coverage makes the
 * score provisional; a DISCOVERY scan has no score.
 */
@Component({
  selector: 'app-risk-page',
  imports: [RouterLink, TranslocoPipe, LocalizedDatePipe],
  changeDetection: ChangeDetectionStrategy.OnPush,
  styles: [`.score { display: flex; align-items: baseline; gap: .5rem; flex-wrap: wrap; } .big { font-size: 2.5rem; }`],
  template: `
    <p><a [routerLink]="['/homes', homeId()]">← {{ 'risk.backToHome' | transloco }}</a></p>
    <section class="card wide">
      <h1>{{ 'risk.title' | transloco }}</h1>
      <p class="muted">{{ 'risk.description' | transloco }}</p>
      @if (problem(); as p) {
        <div class="alert error" role="alert">{{ p.messageKey | transloco }}</div>
      }
      @if (overview(); as o) {
        @if (!o.current) {
          <p class="muted" data-testid="no-score">{{ 'risk.noScan' | transloco }}</p>
        } @else if (o.current.score === null) {
          <div class="alert warning" role="status" data-testid="not-computed">
            {{ 'risk.notComputed.' + o.current.notComputedReason | transloco }}
            @if (o.lastScored) { {{ 'risk.showingLast' | transloco }} }
          </div>
        }
        @if (shown(); as s) {
          <div class="score" data-testid="score">
            <strong class="big">{{ s.score }}</strong><span class="muted">/100</span>
            <span class="badge" [class.err]="s.riskLevel === 'HIGH' || s.riskLevel === 'CRITICAL'"
                  [class.warn]="s.riskLevel === 'MEDIUM'" data-testid="level">{{ 'risk.level.' + s.riskLevel | transloco }}</span>
            <strong data-testid="rating">{{ 'risk.rating.' + s.rating | transloco }}</strong>
          </div>
          <p class="muted small">
            {{ 'risk.computedAt' | transloco }}: {{ s.computedAt | appDate: 'short' }}
            · {{ 'risk.trigger.' + s.trigger | transloco }} · {{ 'risk.profile' | transloco }}: {{ s.scanProfile }}
          </p>
          @if (s.provisional) {
            <div class="alert warning" role="status" data-testid="provisional">
              {{ 'risk.provisional' | transloco: { cap: s.breakdown.provisionalCap ?? 70, uncapped: s.breakdown.uncappedScore } }}
            </div>
          }
          @if (s.delta; as d) {
            <p data-testid="delta">
              {{ 'risk.delta.change' | transloco: { change: signed(d.scoreChange), previous: d.previousScore } }}
            </p>
          }
        }
      }
    </section>

    @if (shown(); as s) {
      <section class="card wide" data-testid="coverage">
        <h2>{{ 'risk.coverage.title' | transloco }}: {{ percent(s.coverage) }}</h2>
        <p class="muted small">{{ 'risk.coverage.description' | transloco }}</p>
        <ul>
          <li>{{ 'risk.coverage.hosts' | transloco: { analyzed: s.coverageDetail.hostsAnalyzed, discovered: s.coverageDetail.hostsDiscovered } }}</li>
          <li>{{ 'risk.coverage.depth' | transloco: { profile: s.coverageDetail.profile } }}</li>
          <li>{{ 'risk.coverage.techniques' | transloco }}:
            @for (t of techniques(s); track t.name) {
              <span class="badge" [class.warn]="!t.ok">{{ t.name }} {{ t.ok ? '✓' : '✗' }}</span>
            }
          </li>
          <li>{{ (s.coverageDetail.routerIntegration ? 'risk.coverage.routerYes' : 'risk.coverage.routerNo') | transloco }}</li>
        </ul>
        @if (s.coverage < 0.8) {
          <p class="small" data-testid="coverage-hint">{{ 'risk.coverage.hint' | transloco }}</p>
        }
      </section>

      <section class="card wide" data-testid="why">
        <h2>{{ 'risk.why.title' | transloco }}</h2>
        <p class="muted small">{{ 'risk.why.formula' | transloco }}</p>
        @if (deductions(s).length === 0) {
          <p class="muted" data-testid="no-deductions">{{ 'risk.why.none' | transloco }}</p>
        } @else {
          <table class="list" data-testid="deductions">
            <thead>
              <tr>
                <th>{{ 'risk.why.finding' | transloco }}</th>
                <th>{{ 'risk.why.device' | transloco }}</th>
                <th>{{ 'risk.why.factors' | transloco }}</th>
                <th>{{ 'risk.why.points' | transloco }}</th>
              </tr>
            </thead>
            <tbody>
              @for (d of deductions(s); track d.findingId) {
                <tr>
                  <td>{{ d.titleKey | transloco: d.params }}
                    <div class="small muted">{{ 'findings.severity.' + d.severity | transloco }} · {{ 'findings.type.' + d.type + '.label' | transloco }}</div>
                  </td>
                  <td>{{ deviceName(s, d) }}</td>
                  <td class="small"><code>{{ factors(d) }}</code></td>
                  <td>−{{ d.value }}</td>
                </tr>
              }
            </tbody>
          </table>
          @if ((s.breakdown.deductionsCount ?? 0) > deductions(s).length) {
            <p class="muted small">{{ 'risk.why.more' | transloco: { count: (s.breakdown.deductionsCount ?? 0) - deductions(s).length } }}</p>
          }
          @if (anyCapped(s)) {
            <p class="muted small" data-testid="capped">{{ 'risk.why.capped' | transloco: { cap: s.breakdown.deviceCap } }}</p>
          }
        }
        @if (s.breakdown.notScored) {
          <p class="muted small">{{ 'risk.why.notScored' | transloco: { count: s.breakdown.notScored } }}</p>
        }
        @if (s.breakdown.excluded?.length) {
          <h3>{{ 'risk.excluded.title' | transloco }}</h3>
          <ul data-testid="excluded">
            @for (e of s.breakdown.excluded; track e.findingId) {
              <li>{{ e.titleKey | transloco: e.params }} — {{ 'findings.status.' + e.status | transloco }}</li>
            }
          </ul>
        }
        <p><a [routerLink]="['/homes', homeId(), 'findings']">{{ 'risk.toFindings' | transloco }} →</a></p>
      </section>

      @if (s.topDevices.length) {
        <section class="card wide" data-testid="top-devices">
          <h2>{{ 'risk.topDevices' | transloco }}</h2>
          <ul>
            @for (t of s.topDevices; track t.deviceId) {
              <li>{{ t.name ?? t.ip ?? '—' }}: −{{ t.applied }}
                @if (t.exposed) { <span class="badge err">{{ 'risk.exposed' | transloco }}</span> }
                @if (t.capped) { <span class="small muted">({{ 'risk.cappedDevice' | transloco: { raw: t.raw } }})</span> }
              </li>
            }
          </ul>
        </section>
      }

      @if (s.delta; as d) {
        <section class="card wide" data-testid="changes">
          <h2>{{ 'risk.delta.title' | transloco }}</h2>
          @if (d.newFindingsCount === 0 && d.removedFindingsCount === 0 && d.newDevicesCount === 0) {
            <p class="muted">{{ 'risk.delta.none' | transloco }}</p>
          }
          @if (d.newFindingsCount) {
            <h3>{{ 'risk.delta.new' | transloco: { count: d.newFindingsCount } }}</h3>
            <ul>
              @for (f of d.newFindings; track f.findingId) {
                <li>{{ f.titleKey ? (f.titleKey | transloco: f.params) : '—' }} (−{{ f.value }})</li>
              }
            </ul>
          }
          @if (d.removedFindingsCount) {
            <h3>{{ 'risk.delta.removed' | transloco: { count: d.removedFindingsCount } }}</h3>
            <ul data-testid="removed">
              @for (f of d.removedFindings; track f.findingId) {
                <li>{{ f.titleKey ? (f.titleKey | transloco: f.params) : '—' }} — {{ 'risk.delta.status.' + f.status | transloco }}</li>
              }
            </ul>
          }
          @if (d.newDevicesCount) {
            <h3>{{ 'risk.delta.devices' | transloco: { count: d.newDevicesCount } }}</h3>
            <ul>
              @for (n of d.newDevices; track n.deviceId) { <li>{{ n.name ?? n.ip ?? '—' }}</li> }
            </ul>
          }
        </section>
      }
    }

    @if (history().length) {
      <section class="card wide">
        <h2>{{ 'risk.history.title' | transloco }}</h2>
        <table class="list" data-testid="history">
          <thead>
            <tr>
              <th>{{ 'risk.history.date' | transloco }}</th>
              <th>{{ 'risk.history.score' | transloco }}</th>
              <th>{{ 'risk.history.change' | transloco }}</th>
              <th>{{ 'risk.coverage.title' | transloco }}</th>
              <th>{{ 'risk.history.cause' | transloco }}</th>
            </tr>
          </thead>
          <tbody>
            @for (h of history(); track h.id) {
              <tr>
                <td>{{ h.computedAt | appDate: 'short' }}</td>
                <td>{{ h.score ?? '—' }} @if (h.provisional && h.score !== null) { * }</td>
                <td>{{ h.scoreChange === null ? '' : signed(h.scoreChange) }}</td>
                <td>{{ percent(h.coverage) }}</td>
                <td>{{ 'risk.trigger.' + h.trigger | transloco }} · {{ h.scanProfile }}</td>
              </tr>
            }
          </tbody>
        </table>
        <p class="muted small">{{ 'risk.history.provisionalNote' | transloco }}</p>
      </section>
    }
  `,
})
export class RiskPage implements OnInit {
  private readonly api = inject(RiskApi);

  /** Route parameter :id (component input binding). */
  readonly homeId = input.required<string>({ alias: 'id' });

  readonly overview = signal<RiskOverview | null>(null);
  readonly history = signal<RiskHistoryEntry[]>([]);
  readonly problem = signal<ApiProblem | null>(null);

  /** Snapshot whose score is shown: the current one, or the last computed after a DISCOVERY scan. */
  readonly shown = computed<RiskSnapshot | null>(() => {
    const o = this.overview();
    if (!o?.current) {
      return null;
    }
    return o.current.score !== null ? o.current : o.lastScored;
  });

  ngOnInit(): void {
    void this.load();
  }

  async load(): Promise<void> {
    this.problem.set(null);
    try {
      const [overview, history] = await Promise.all([
        firstValueFrom(this.api.current(this.homeId())),
        firstValueFrom(this.api.history(this.homeId())),
      ]);
      this.overview.set(overview);
      this.history.set(history);
    } catch (error) {
      this.problem.set(toApiProblem(error));
    }
  }

  deductions(s: RiskSnapshot): RiskDeduction[] {
    return s.breakdown.deductions ?? [];
  }

  anyCapped(s: RiskSnapshot): boolean {
    return (s.breakdown.devices ?? []).some((d) => d.capped);
  }

  deviceName(s: RiskSnapshot, d: RiskDeduction): string {
    const device = (s.breakdown.devices ?? []).find((x) => x.deviceId === d.deviceId);
    return device?.name ?? device?.ip ?? '—';
  }

  /** base × type × confidence × criticality × exposure × KEV (factors equal to 1 are still shown). */
  factors(d: RiskDeduction): string {
    const f = d.factors;
    return [f.base, f.type, f.confidence, f.criticality, f.exposure, f.kev].join(' × ');
  }

  techniques(s: RiskSnapshot): { name: string; ok: boolean }[] {
    return Object.entries(s.coverageDetail.techniques ?? {}).map(([name, ok]) => ({ name, ok }));
  }

  percent(value: number): string {
    return `${Math.round(value * 100)}%`;
  }

  signed(value: number): string {
    return value > 0 ? `+${value}` : `${value}`;
  }
}

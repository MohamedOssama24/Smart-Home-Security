import { ChangeDetectionStrategy, Component, OnInit, inject, input, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { TranslocoPipe } from '@jsverse/transloco';
import { firstValueFrom } from 'rxjs';
import { ApiProblem, toApiProblem } from '../../core/api/api-error';
import { AuthService } from '../../core/auth/auth.service';
import {
  FINDING_SEVERITIES, FINDING_STATUSES, FINDING_TYPES, Finding, FindingDetail, FindingEvidence, FindingsApi,
  TRIAGE_STATUSES,
} from '../../core/findings/findings.api';
import { LocalizedDatePipe } from '../../core/i18n/localized-date.pipe';

/**
 * Security findings of a home (Milestone 10): what was found, how sure we are (a confirmed
 * vulnerability is not a potential risk), what it means, what to do, the evidence and the
 * matched CVEs. A user can acknowledge a finding or mark it as a false positive / accepted
 * risk with a reason; only a later scan marks it as resolved.
 */
@Component({
  selector: 'app-findings-page',
  imports: [RouterLink, FormsModule, TranslocoPipe, LocalizedDatePipe],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <p><a [routerLink]="['/homes', homeId()]">← {{ 'findings.backToHome' | transloco }}</a></p>
    <section class="card wide">
      <h1>{{ 'findings.title' | transloco }}</h1>
      <p class="muted">{{ 'findings.description' | transloco }}</p>
      @if (problem(); as p) {
        <div class="alert error" role="alert">{{ p.messageKey | transloco }}</div>
      }
      <div class="filters" data-testid="filters">
        <label>{{ 'findings.filter.status' | transloco }}
          <select data-testid="filter-status" [ngModel]="status()" (ngModelChange)="status.set($event); load()">
            <option value="">{{ 'findings.filter.all' | transloco }}</option>
            @for (s of statuses; track s) {
              <option [value]="s">{{ 'findings.status.' + s | transloco }}</option>
            }
          </select>
        </label>
        <label>{{ 'findings.filter.severity' | transloco }}
          <select data-testid="filter-severity" [ngModel]="severity()" (ngModelChange)="severity.set($event); load()">
            <option value="">{{ 'findings.filter.all' | transloco }}</option>
            @for (s of severities; track s) {
              <option [value]="s">{{ 'findings.severity.' + s | transloco }}</option>
            }
          </select>
        </label>
        <label>{{ 'findings.filter.type' | transloco }}
          <select data-testid="filter-type" [ngModel]="type()" (ngModelChange)="type.set($event); load()">
            <option value="">{{ 'findings.filter.all' | transloco }}</option>
            @for (t of types; track t) {
              <option [value]="t">{{ 'findings.type.' + t + '.label' | transloco }}</option>
            }
          </select>
        </label>
      </div>
      @if (findings().length === 0) {
        <p class="muted" data-testid="empty">{{ 'findings.empty' | transloco }}</p>
      } @else {
        <table class="list" data-testid="findings">
          <thead>
            <tr>
              <th>{{ 'findings.severityLabel' | transloco }}</th>
              <th>{{ 'findings.finding' | transloco }}</th>
              <th>{{ 'findings.device' | transloco }}</th>
              <th>{{ 'findings.statusLabel' | transloco }}</th>
              <th>{{ 'findings.lastDetected' | transloco }}</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            @for (f of findings(); track f.id) {
              <tr [class.muted]="!active(f)">
                <td><span class="badge" [class.err]="high(f.severity)" [class.warn]="f.severity === 'MEDIUM'">{{ 'findings.severity.' + f.severity | transloco }}</span></td>
                <td>
                  {{ f.titleKey | transloco: f.params }}
                  <div class="small muted">{{ 'findings.type.' + f.type + '.label' | transloco }}</div>
                </td>
                <td>{{ f.device.name ?? f.device.ip ?? '—' }}
                  @if (f.port) { <code>{{ f.protocol }}/{{ f.port }}</code> }
                </td>
                <td>{{ 'findings.status.' + f.status | transloco }}</td>
                <td>{{ f.lastDetectedAt | appDate: 'short' }}</td>
                <td><button type="button" (click)="open(f)" [disabled]="busy()">{{ 'findings.show' | transloco }}</button></td>
              </tr>
            }
          </tbody>
        </table>
      }
    </section>

    @if (selected(); as d) {
      <section class="card wide" data-testid="finding-detail">
        <h2>{{ d.finding.titleKey | transloco: d.finding.params }}</h2>
        <p>
          <span class="badge" [class.err]="high(d.finding.severity)" [class.warn]="d.finding.severity === 'MEDIUM'">{{ 'findings.severity.' + d.finding.severity | transloco }}</span>
          <strong data-testid="type">{{ 'findings.type.' + d.finding.type + '.label' | transloco }}</strong>
          · {{ 'findings.confidenceLabel' | transloco }}: {{ 'findings.confidence.' + d.finding.confidence | transloco }}
          · {{ 'findings.status.' + d.finding.status | transloco }}
        </p>
        <p class="muted small" data-testid="type-explanation">{{ 'findings.type.' + d.finding.type + '.explanation' | transloco }}</p>

        <h3>{{ 'findings.whatItMeans' | transloco }}</h3>
        <p data-testid="meaning">{{ descriptionKey(d.finding) | transloco: d.finding.params }}</p>
        <h3>{{ 'findings.whatToDo' | transloco }}</h3>
        <p data-testid="recommendation">{{ d.finding.recommendationKey | transloco: d.finding.params }}</p>

        <p class="muted small">
          {{ 'findings.firstDetected' | transloco }}: {{ d.finding.firstDetectedAt | appDate: 'short' }}
          · {{ 'findings.lastDetected' | transloco }}: {{ d.finding.lastDetectedAt | appDate: 'short' }}
          @if (d.finding.resolvedAt) { · {{ 'findings.resolvedAt' | transloco }}: {{ d.finding.resolvedAt | appDate: 'short' }} }
        </p>
        @if (d.finding.statusReason) {
          <p data-testid="status-reason">{{ 'findings.reason' | transloco }}: {{ d.finding.statusReason }}</p>
        }

        @if (d.vulnerabilities.length) {
          <h3>{{ 'findings.cves' | transloco }}</h3>
          <p class="muted small">{{ 'findings.cveNote' | transloco }}</p>
          <table class="list" data-testid="cves">
            <tbody>
              @for (c of d.vulnerabilities; track c.cveId) {
                <tr>
                  <td><code>{{ c.cveId }}</code>
                    @if (c.kev) { <span class="badge err" data-testid="kev">{{ 'findings.kev' | transloco }}</span> }
                  </td>
                  <td>{{ c.severity ?? '—' }} @if (c.cvssScore !== null) { ({{ c.cvssScore }}) }</td>
                  <td>{{ 'findings.match.' + c.matchQuality | transloco }}</td>
                  <td class="small">
                    @if (c.epssScore !== null) { {{ 'findings.epss' | transloco: { value: percent(c.epssScore) } }} }
                    <div class="muted">{{ c.description }}</div>
                  </td>
                </tr>
              }
            </tbody>
          </table>
          @if (d.matchedCves > d.vulnerabilities.length) {
            <p class="muted small">{{ 'findings.moreCves' | transloco: { count: d.matchedCves - d.vulnerabilities.length } }}</p>
          }
        }

        <h3>{{ 'findings.evidence' | transloco }}</h3>
        <ul data-testid="evidence">
          @for (e of d.evidence; track $index) {
            <li><span class="small muted">{{ e.collectedAt | appDate: 'short' }} · {{ e.type }}</span>
              <code class="small">{{ evidenceText(e) }}</code></li>
          }
        </ul>

        @if (canTriage() && d.finding.status !== 'RESOLVED') {
          <h3>{{ 'findings.triage.title' | transloco }}</h3>
          <form (ngSubmit)="triage(d)" data-testid="triage-form">
            <label>{{ 'findings.triage.status' | transloco }}
              <select name="target" data-testid="triage-status" [ngModel]="target()" (ngModelChange)="target.set($event)">
                @for (s of triageStatuses; track s) {
                  <option [value]="s">{{ 'findings.status.' + s | transloco }}</option>
                }
              </select>
            </label>
            <label>{{ 'findings.triage.reason' | transloco }}
              <textarea name="reason" maxlength="500" data-testid="triage-reason" [ngModel]="reason()"
                        (ngModelChange)="reason.set($event)"></textarea>
            </label>
            <p class="muted small">{{ 'findings.triage.note' | transloco }}</p>
            <button type="submit" [disabled]="busy() || (target() !== 'OPEN' && !reason().trim())">
              {{ 'findings.triage.save' | transloco }}</button>
          </form>
        }
      </section>
    }
  `,
})
export class FindingsPage implements OnInit {
  private readonly api = inject(FindingsApi);
  private readonly auth = inject(AuthService);

  /** Route parameter :id (component input binding). */
  readonly homeId = input.required<string>({ alias: 'id' });

  readonly statuses = FINDING_STATUSES;
  readonly severities = FINDING_SEVERITIES;
  readonly types = FINDING_TYPES;
  readonly triageStatuses = TRIAGE_STATUSES;

  readonly findings = signal<Finding[]>([]);
  readonly selected = signal<FindingDetail | null>(null);
  readonly status = signal('');
  readonly severity = signal('');
  readonly type = signal('');
  readonly target = signal<string>('ACKNOWLEDGED');
  readonly reason = signal('');
  readonly busy = signal(false);
  readonly problem = signal<ApiProblem | null>(null);

  canTriage(): boolean {
    return this.auth.hasPermission('finding:triage');
  }

  high(severity: string): boolean {
    return severity === 'CRITICAL' || severity === 'HIGH';
  }

  active(f: Finding): boolean {
    return f.status === 'OPEN' || f.status === 'ACKNOWLEDGED';
  }

  /** "What it means" text: same key as the title, ".description" instead of ".title". */
  descriptionKey(f: Finding): string {
    return f.titleKey.replace(/\.title$/, '.description');
  }

  percent(value: number): string {
    return `${Math.round(value * 1000) / 10}%`;
  }

  /** Evidence as declared by the device or computed by the analysis (never interpreted as HTML). */
  evidenceText(e: FindingEvidence): string {
    return Object.entries(e.data)
      .map(([k, v]) => `${k}: ${typeof v === 'object' ? JSON.stringify(v) : String(v)}`)
      .join(' · ');
  }

  ngOnInit(): void {
    void this.load();
  }

  async load(): Promise<void> {
    await this.run(async () => this.findings.set(await firstValueFrom(this.api.list(this.homeId(), {
      status: this.status(), severity: this.severity(), type: this.type(),
    }))));
  }

  async open(f: Finding): Promise<void> {
    await this.run(async () => {
      this.selected.set(await firstValueFrom(this.api.get(f.id)));
      this.target.set(f.status === 'OPEN' ? 'ACKNOWLEDGED' : 'OPEN');
      this.reason.set('');
    });
  }

  async triage(d: FindingDetail): Promise<void> {
    await this.run(async () => {
      const text = this.reason().trim();
      const updated = await firstValueFrom(this.api.changeStatus(d.finding.id, this.target(), text || null));
      this.selected.set(updated);
      this.findings.update((list) => list.map((x) => (x.id === updated.finding.id ? updated.finding : x)));
      this.reason.set('');
    });
  }

  private async run(action: () => Promise<void>): Promise<void> {
    this.busy.set(true);
    this.problem.set(null);
    try {
      await action();
    } catch (error) {
      this.problem.set(toApiProblem(error));
    } finally {
      this.busy.set(false);
    }
  }
}

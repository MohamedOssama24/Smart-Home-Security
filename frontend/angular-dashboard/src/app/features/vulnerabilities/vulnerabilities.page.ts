import { ChangeDetectionStrategy, Component, OnInit, computed, inject, input, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { TranslocoPipe } from '@jsverse/transloco';
import { firstValueFrom } from 'rxjs';
import { ApiProblem, toApiProblem } from '../../core/api/api-error';
import { FindingsApi, HomeVulnerability } from '../../core/findings/findings.api';

const SEVERITY_ORDER: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

/**
 * Known vulnerabilities (CVE) of the home (Milestone 12): every CVE matched to a device by
 * the security analysis, actively exploited (KEV) first, then by CVSS. The match is based on
 * the product and version declared by the service, not verified: the page says so.
 */
@Component({
  selector: 'app-vulnerabilities-page',
  imports: [RouterLink, TranslocoPipe],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <p><a [routerLink]="['/homes', homeId()]">← {{ 'risk.backToHome' | transloco }}</a></p>
    <section class="card wide">
      <h1>{{ 'vulnerabilities.title' | transloco }}</h1>
      <p class="muted">{{ 'vulnerabilities.description' | transloco }}</p>
      @if (problem(); as p) {
        <div class="alert error" role="alert">{{ p.messageKey | transloco }}</div>
      }
      @if (all(); as list) {
        @if (list.length === 0) {
          <p class="muted" data-testid="no-cves">{{ 'vulnerabilities.none' | transloco }}</p>
        } @else {
          <div class="actions">
            <label><input type="checkbox" [checked]="kevOnly()" (change)="kevOnly.set($any($event.target).checked)"
                          data-testid="kev-only" /> {{ 'vulnerabilities.kevOnly' | transloco }}</label>
            <label>{{ 'findings.filter.severity' | transloco }}
              <select [value]="severity()" (change)="severity.set($any($event.target).value)" data-testid="severity">
                <option value="">{{ 'findings.filter.all' | transloco }}</option>
                @for (s of severities; track s) {
                  <option [value]="s">{{ 'findings.severity.' + s | transloco }}</option>
                }
              </select>
            </label>
            <span class="muted small" data-testid="count">{{ 'vulnerabilities.count' | transloco: { shown: shown().length, total: list.length } }}</span>
          </div>
          <table class="list" data-testid="cves">
            <thead>
              <tr>
                <th>CVE</th>
                <th>{{ 'findings.filter.severity' | transloco }}</th>
                <th>{{ 'vulnerabilities.product' | transloco }}</th>
                <th>{{ 'vulnerabilities.device' | transloco }}</th>
                <th>{{ 'vulnerabilities.match' | transloco }}</th>
                <th>{{ 'findings.filter.status' | transloco }}</th>
              </tr>
            </thead>
            <tbody>
              @for (v of shown(); track v.findingId + v.cveId) {
                <tr>
                  <td>
                    <a [href]="'https://nvd.nist.gov/vuln/detail/' + v.cveId" target="_blank" rel="noopener noreferrer">{{ v.cveId }}</a>
                    @if (v.kev) {
                      <div><span class="badge err" data-testid="kev">{{ 'findings.kev' | transloco }}</span></div>
                    }
                  </td>
                  <td>
                    @if (v.severity) {
                      <span class="badge" [class.err]="v.severity === 'CRITICAL' || v.severity === 'HIGH'"
                            [class.warn]="v.severity === 'MEDIUM'">{{ 'findings.severity.' + v.severity | transloco }}</span>
                    }
                    @if (v.cvssScore !== null) { <div class="small">CVSS {{ v.cvssScore }}</div> }
                    @if (v.epssScore !== null) { <div class="small muted">EPSS {{ percent(v.epssScore) }}</div> }
                  </td>
                  <td>{{ v.product }} {{ v.version }}</td>
                  <td>{{ v.device.name || v.device.ip }}
                    @if (v.device.name && v.device.ip) { <div class="small muted">{{ v.device.ip }}</div> }
                  </td>
                  <td class="small">{{ 'findings.match.' + v.matchQuality | transloco }}
                    <div class="muted">{{ 'findings.type.' + v.findingType + '.label' | transloco }}</div>
                  </td>
                  <td>{{ 'findings.status.' + v.findingStatus | transloco }}</td>
                </tr>
              }
            </tbody>
          </table>
          <p class="muted small">{{ 'findings.cveNote' | transloco }}</p>
          <p class="muted small">{{ 'vulnerabilities.limit' | transloco }}</p>
        }
        <p><a [routerLink]="['/homes', homeId(), 'findings']">{{ 'risk.toFindings' | transloco }} →</a></p>
      }
    </section>
  `,
})
export class VulnerabilitiesPage implements OnInit {
  /** Route parameter (component input binding). */
  readonly homeId = input.required<string>({ alias: 'id' });
  private readonly api = inject(FindingsApi);
  protected readonly severities = Object.keys(SEVERITY_ORDER);

  readonly all = signal<HomeVulnerability[] | null>(null);
  readonly problem = signal<ApiProblem | null>(null);
  readonly kevOnly = signal(false);
  readonly severity = signal('');

  readonly shown = computed(() =>
    (this.all() ?? [])
      .filter((v) => !this.kevOnly() || v.kev)
      .filter((v) => !this.severity() || v.severity === this.severity())
      .sort(
        (a, b) =>
          Number(b.kev) - Number(a.kev) ||
          (b.cvssScore ?? -1) - (a.cvssScore ?? -1) ||
          (SEVERITY_ORDER[a.severity ?? ''] ?? 9) - (SEVERITY_ORDER[b.severity ?? ''] ?? 9) ||
          a.cveId.localeCompare(b.cveId),
      ),
  );

  async ngOnInit(): Promise<void> {
    try {
      this.all.set(await firstValueFrom(this.api.homeVulnerabilities(this.homeId())));
    } catch (e) {
      this.problem.set(toApiProblem(e));
    }
  }

  protected percent(value: number): string {
    return `${(value * 100).toFixed(1)}%`;
  }
}

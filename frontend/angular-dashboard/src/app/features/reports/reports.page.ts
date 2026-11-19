import { ChangeDetectionStrategy, Component, OnDestroy, OnInit, computed, inject, input, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { TranslocoPipe } from '@jsverse/transloco';
import { firstValueFrom } from 'rxjs';
import { ApiProblem, toApiProblem } from '../../core/api/api-error';
import { AuthService } from '../../core/auth/auth.service';
import { LanguageService } from '../../core/i18n/language.service';
import { LocalizedDatePipe } from '../../core/i18n/localized-date.pipe';
import { Report, ReportsApi } from '../../core/reports/reports.api';
import { Scan, ScansApi } from '../../core/scans/scans.api';

const MAX_POLLS = 60;

/**
 * PDF security reports of the home (Milestone 13): generated from a completed scan in Italian
 * or English, in the background, then downloaded. Written for non-technical readers: score,
 * coverage, open issues with what to do, devices and the limits of the analysis.
 */
@Component({
  selector: 'app-reports-page',
  imports: [RouterLink, TranslocoPipe, LocalizedDatePipe],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <p><a [routerLink]="['/homes', homeId()]">← {{ 'risk.backToHome' | transloco }}</a></p>
    <section class="card wide">
      <h1>{{ 'reports.title' | transloco }}</h1>
      <p class="muted">{{ 'reports.description' | transloco }}</p>
      @if (problem(); as p) {
        <div class="alert error" role="alert" data-testid="problem">{{ p.messageKey | transloco }}</div>
      }
      @if (canGenerate()) {
        @if (completed().length === 0) {
          <p class="muted" data-testid="no-scans">{{ 'reports.noScans' | transloco }}</p>
        } @else {
          <div class="actions" data-testid="generate-form">
            <label>{{ 'reports.scan' | transloco }}
              <select [value]="scanId()" (change)="scanId.set($any($event.target).value)" data-testid="scan">
                @for (s of completed(); track s.id) {
                  <option [value]="s.id" [selected]="s.id === scanId()">{{ s.completedAt | appDate: 'short' }} · {{ 'scans.profiles.' + s.profile | transloco }}</option>
                }
              </select>
            </label>
            <label>{{ 'reports.language' | transloco }}
              <select [value]="locale()" (change)="locale.set($any($event.target).value)" data-testid="locale">
                <option value="it" [selected]="locale() === 'it'">Italiano</option>
                <option value="en" [selected]="locale() === 'en'">English</option>
              </select>
            </label>
            <button type="button" class="primary" (click)="generate()" [disabled]="busy()" data-testid="generate">{{ 'reports.generate' | transloco }}</button>
          </div>
        }
      }
      @if (reports(); as list) {
        @if (list.length === 0) {
          <p class="muted" data-testid="no-reports">{{ 'reports.none' | transloco }}</p>
        } @else {
          <table class="list" data-testid="reports">
            <thead>
              <tr>
                <th>{{ 'reports.requestedAt' | transloco }}</th>
                <th>{{ 'reports.scan' | transloco }}</th>
                <th>{{ 'reports.language' | transloco }}</th>
                <th>{{ 'reports.statusLabel' | transloco }}</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              @for (r of list; track r.id) {
                <tr [attr.data-testid]="'report-' + r.id">
                  <td>{{ r.requestedAt | appDate: 'short' }}</td>
                  <td>{{ scanLabel(r.scanId) | appDate: 'short' }}</td>
                  <td>{{ r.locale.toUpperCase() }}</td>
                  <td>
                    <span class="badge" [class.ok]="r.status === 'READY'" [class.err]="r.status === 'FAILED'"
                          [class.warn]="r.status === 'PENDING'" data-testid="status">{{ 'reports.status.' + r.status | transloco }}</span>
                    @if (r.status === 'READY') {
                      <div class="small muted">{{ 'reports.size' | transloco: { pages: r.pages, kb: kb(r.sizeBytes) } }}</div>
                    }
                  </td>
                  <td>
                    @if (r.status === 'READY') {
                      <button type="button" (click)="download(r)" data-testid="download">{{ 'reports.download' | transloco }}</button>
                    }
                  </td>
                </tr>
              }
            </tbody>
          </table>
        }
      }
    </section>
  `,
})
export class ReportsPage implements OnInit, OnDestroy {
  /** Route parameter (component input binding). */
  readonly homeId = input.required<string>({ alias: 'id' });
  private readonly api = inject(ReportsApi);
  private readonly scans = inject(ScansApi);
  private readonly auth = inject(AuthService);
  private readonly language = inject(LanguageService);
  /** Delay between two status checks of a report being generated (ms). */
  pollMs = 1500;
  private destroyed = false;

  readonly reports = signal<Report[] | null>(null);
  readonly history = signal<Scan[]>([]);
  readonly problem = signal<ApiProblem | null>(null);
  readonly busy = signal(false);
  readonly scanId = signal('');
  readonly locale = signal<'it' | 'en'>('it');

  readonly completed = computed(() =>
    this.history().filter((s) => s.status === 'COMPLETED' || s.status === 'COMPLETED_WITH_WARNINGS'),
  );

  /** Navigation hint only: the backend checks report:generate on the home. */
  protected canGenerate(): boolean {
    return this.auth.hasPermission('report:generate');
  }

  async ngOnInit(): Promise<void> {
    this.locale.set(this.language.current() === 'en' ? 'en' : 'it');
    try {
      this.reports.set(await firstValueFrom(this.api.forHome(this.homeId())));
    } catch (e) {
      this.problem.set(toApiProblem(e));
      return;
    }
    try {
      this.history.set(await firstValueFrom(this.scans.history(this.homeId())));
      this.scanId.set(this.completed()[0]?.id ?? '');
    } catch {
      this.history.set([]); // without scan:read the list of reports is still shown
    }
    for (const r of this.reports() ?? []) {
      if (r.status === 'PENDING') {
        void this.poll(r.id);
      }
    }
  }

  ngOnDestroy(): void {
    this.destroyed = true;
  }

  protected scanLabel(scanId: string): string | null {
    return this.history().find((s) => s.id === scanId)?.completedAt ?? null;
  }

  protected kb(bytes: number | null): number {
    return Math.max(1, Math.round((bytes ?? 0) / 1024));
  }

  protected async generate(): Promise<void> {
    if (!this.scanId()) {
      return;
    }
    this.busy.set(true);
    this.problem.set(null);
    try {
      const report = await firstValueFrom(this.api.request(this.scanId(), this.locale()));
      this.reports.update((list) => [report, ...(list ?? [])]);
      void this.poll(report.id);
    } catch (e) {
      this.problem.set(toApiProblem(e));
    } finally {
      this.busy.set(false);
    }
  }

  /** Checks the report until it is READY or FAILED. */
  private async poll(id: string): Promise<void> {
    for (let i = 0; i < MAX_POLLS && !this.destroyed; i++) {
      await new Promise((resolve) => setTimeout(resolve, this.pollMs));
      try {
        const report = await firstValueFrom(this.api.get(id));
        this.reports.update((list) => (list ?? []).map((r) => (r.id === id ? report : r)));
        if (report.status !== 'PENDING') {
          return;
        }
      } catch (e) {
        this.problem.set(toApiProblem(e));
        return;
      }
    }
  }

  protected async download(r: Report): Promise<void> {
    try {
      const blob = await firstValueFrom(this.api.download(r.id));
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `security-report-${(r.generatedAt ?? r.requestedAt).slice(0, 10)}-${r.locale}.pdf`;
      a.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (e) {
      this.problem.set(toApiProblem(e));
    }
  }
}

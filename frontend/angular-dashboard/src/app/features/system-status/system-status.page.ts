import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core';
import { TranslocoPipe } from '@jsverse/transloco';
import { BackendStatus, SystemStatusService } from '../../core/system/system-status.service';

@Component({
  selector: 'app-system-status-page',
  imports: [TranslocoPipe],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <section class="card" aria-live="polite">
      <h1>{{ 'systemStatus.title' | transloco }}</h1>
      <p class="muted">{{ 'systemStatus.description' | transloco }}</p>

      <div class="status-row">
        <span>{{ 'systemStatus.backend' | transloco }}</span>
        @switch (status()) {
          @case (null) {
            <span class="badge" data-testid="backend-status">{{ 'systemStatus.checking' | transloco }}</span>
          }
          @default {
            <span class="badge" [class]="'badge status-' + status()" data-testid="backend-status">
              {{ 'systemStatus.state.' + status() | transloco }}
            </span>
          }
        }
      </div>

      <button type="button" (click)="refresh()" [disabled]="status() === null">
        {{ 'systemStatus.refresh' | transloco }}
      </button>
    </section>
  `,
  styles: `
    .card { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 24px; max-width: 560px; }
    h1 { font-size: 1.25rem; margin: 0 0 8px; }
    .muted { color: var(--text-muted); margin: 0 0 20px; }
    .status-row { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
    .badge { padding: 4px 10px; border-radius: 999px; font-size: 0.85rem; font-weight: 600; background: var(--border); }
    .status-UP { background: var(--ok-bg); color: var(--ok-fg); }
    .status-DOWN, .status-UNREACHABLE { background: var(--err-bg); color: var(--err-fg); }
    button { padding: 8px 16px; border-radius: 8px; border: 1px solid var(--border); background: var(--surface); color: var(--text); cursor: pointer; }
    button:disabled { opacity: 0.6; cursor: default; }
  `,
})
export class SystemStatusPage {
  private readonly systemStatus = inject(SystemStatusService);

  /** null while a check is in progress. */
  readonly status = signal<BackendStatus | null>(null);

  constructor() {
    this.refresh();
  }

  refresh(): void {
    this.status.set(null);
    this.systemStatus.backendStatus().subscribe((status) => this.status.set(status));
  }
}

import { ChangeDetectionStrategy, Component, OnInit, inject, input, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { TranslocoPipe } from '@jsverse/transloco';
import { firstValueFrom } from 'rxjs';
import { ApiProblem, toApiProblem } from '../../core/api/api-error';
import { AuthService } from '../../core/auth/auth.service';
import { DEVICE_CATEGORIES, Device, DeviceServices, DevicesApi } from '../../core/devices/devices.api';
import { LocalizedDatePipe } from '../../core/i18n/localized-date.pipe';
import { PortTableComponent } from '../scans/port-table.component';

/**
 * Device inventory of a home (Milestone 8): what was identified, how confidently and from
 * which sources, manual classification and its history. Detected values are hints, never
 * certainties: a weak hint alone leaves the device "unknown".
 */
@Component({
  selector: 'app-devices-page',
  imports: [RouterLink, TranslocoPipe, LocalizedDatePipe, PortTableComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <p><a [routerLink]="['/homes', homeId()]">← {{ 'devices.backToHome' | transloco }}</a></p>
    <section class="card wide">
      <h1>{{ 'devices.title' | transloco }}</h1>
      <p class="muted">{{ 'devices.description' | transloco }}</p>
      @if (problem(); as p) {
        <div class="alert error" role="alert">{{ p.messageKey | transloco }}</div>
      }
      @if (devices().length === 0) {
        <p class="muted" data-testid="empty">{{ 'devices.empty' | transloco }}</p>
      } @else {
        <table class="list" data-testid="inventory">
          <thead>
            <tr>
              <th>{{ 'devices.name' | transloco }}</th>
              <th>{{ 'devices.category' | transloco }}</th>
              <th>{{ 'devices.ip' | transloco }}</th>
              <th>{{ 'devices.mac' | transloco }}</th>
              <th>{{ 'devices.manufacturer' | transloco }}</th>
              <th>{{ 'devices.lastSeen' | transloco }}</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            @for (d of devices(); track d.id) {
              <tr>
                <td>{{ d.hostname ?? '—' }}</td>
                <td>
                  {{ 'devices.categories.' + d.category | transloco }}
                  @if (d.manualCategory) {
                    <span class="badge">{{ 'devices.manual' | transloco }}</span>
                  } @else if (d.detectedCategoryConfidence) {
                    <span class="badge">{{ 'devices.confidence.' + d.detectedCategoryConfidence | transloco }}</span>
                  }
                </td>
                <td><code>{{ d.ip ?? '—' }}</code></td>
                <td>
                  <code>{{ d.mac ?? '—' }}</code>
                  @if (d.macRandomized) {
                    <span class="badge warn">{{ 'devices.randomized' | transloco }}</span>
                  }
                </td>
                <td>{{ d.manufacturer ?? '—' }}</td>
                <td>{{ d.lastSeenAt | appDate: 'short' }}</td>
                <td><button type="button" (click)="open(d)" [disabled]="busy()">{{ 'devices.show' | transloco }}</button></td>
              </tr>
            }
          </tbody>
        </table>
      }
    </section>

    @if (selected(); as d) {
      <section class="card wide" data-testid="device-detail">
        <h2>{{ d.hostname ?? d.ip ?? d.mac }}</h2>
        <p>
          <strong>{{ 'devices.categories.' + d.category | transloco }}</strong>
          · {{ 'devices.overall' | transloco }}: {{ 'devices.confidence.' + d.overallConfidence | transloco }}
        </p>
        @if (d.suggestedCategory) {
          <div class="alert warning" role="status" data-testid="suggestion">
            {{ 'devices.suggestion' | transloco: { category: ('devices.categories.' + d.suggestedCategory | transloco) } }}
          </div>
        }
        @if (d.macRandomized) {
          <p class="muted" data-testid="randomized-note">{{ 'devices.randomizedNote' | transloco }}
            @if (sameAs(d); as other) { {{ 'devices.probableSameAs' | transloco: { name: other } }} }
          </p>
        }

        @if (canClassify()) {
          <label>
            {{ 'devices.setCategory' | transloco }}
            <select data-testid="category-select" [value]="d.manualCategory ?? ''" (change)="classify(d, $any($event.target).value)"
                    [disabled]="busy()">
              <option value="">{{ 'devices.automatic' | transloco }} ({{ 'devices.categories.' + d.detectedCategory | transloco }})</option>
              @for (c of categories; track c) {
                <option [value]="c">{{ 'devices.categories.' + c | transloco }}</option>
              }
            </select>
          </label>
        }

        <h3>{{ 'devices.identified' | transloco }}</h3>
        <table class="list" data-testid="identifications">
          <tbody>
            @for (i of d.identifications ?? []; track i.field) {
              <tr>
                <td>{{ 'devices.fields.' + i.field | transloco }}</td>
                <td><strong>{{ i.value }}</strong></td>
                <td>
                  <span class="badge" [class.ok]="i.confidence === 'HIGH'" [class.warn]="i.confidence === 'LOW'">
                    {{ 'devices.confidence.' + i.confidence | transloco }}</span>
                  @if (i.conflict) {
                    <span class="badge err">{{ 'devices.conflict' | transloco }}</span>
                  }
                </td>
                <td class="small">
                  @for (s of i.sources; track $index) {
                    <div [class.muted]="!s.agrees">{{ s.source }}: {{ s.value }}@if (!s.agrees) { ({{ 'devices.disagrees' | transloco }}) }</div>
                  }
                </td>
              </tr>
            }
          </tbody>
        </table>

        @if (d.classification?.matches?.length) {
          <h3>{{ 'devices.why' | transloco }}</h3>
          <ul data-testid="matches">
            @for (m of d.classification!.matches!; track m.rule) {
              <li><code>{{ m.rule }}</code> → {{ 'devices.categories.' + m.category | transloco }}
                <span class="badge">{{ 'devices.strength.' + m.strength | transloco }}</span>
                <span class="muted">{{ m.sources.join(', ') }}</span></li>
            }
          </ul>
          <p class="muted small">{{ 'devices.ruleset' | transloco: { version: d.rulesetVersion } }}</p>
        }

        <h3>{{ 'ports.title' | transloco }}</h3>
        @if (d.services; as svc) {
          <p class="muted small" data-testid="port-summary">
            {{ svc.scannedAt | appDate: 'short' }} · {{ 'ports.summary' | transloco: summary(svc) }}
          </p>
          @if (svc.summary.paused) {
            <div class="alert warning" role="status">{{ 'scans.warning.PORT_SCAN_HOST_PAUSED' | transloco }}</div>
          }
          <app-port-table [ports]="svc.ports" />
          @if (svc.protocols.length) {
            <p data-testid="protocols">{{ 'ports.protocols' | transloco }}:
              @for (p of svc.protocols; track p.protocol) {
                <span class="badge" [class.warn]="p.confidence === 'LOW'">{{ p.protocol }}</span>
              }
            </p>
          }
        } @else {
          <p class="muted" data-testid="ports-not-scanned">{{ 'ports.notScanned' | transloco }}</p>
        }

        <h3>{{ 'devices.history' | transloco }}</h3>
        <table class="list" data-testid="category-history">
          <tbody>
            @for (c of d.categoryHistory ?? []; track $index) {
              <tr>
                <td>{{ c.changedAt | appDate: 'short' }}</td>
                <td>{{ 'devices.changeSource.' + c.source | transloco }}</td>
                <td>{{ label(c.oldCategory) | transloco }} → {{ label(c.newCategory) | transloco }}</td>
              </tr>
            }
          </tbody>
        </table>
      </section>
    }
  `,
})
export class DevicesPage implements OnInit {
  private readonly api = inject(DevicesApi);
  private readonly auth = inject(AuthService);

  /** Route parameter :id (component input binding). */
  readonly homeId = input.required<string>({ alias: 'id' });

  readonly categories = DEVICE_CATEGORIES.filter((c) => c !== 'UNKNOWN_DEVICE');
  readonly devices = signal<Device[]>([]);
  readonly selected = signal<Device | null>(null);
  readonly busy = signal(false);
  readonly problem = signal<ApiProblem | null>(null);

  canClassify(): boolean {
    return this.auth.hasPermission('device:classify');
  }

  label(category: string | null): string {
    return category ? `devices.categories.${category}` : 'devices.automatic';
  }

  /** Name of the device that a randomized MAC probably belongs to, if known. */
  sameAs(d: Device): string | null {
    const other = d.probableSameAs ? this.devices().find((x) => x.id === d.probableSameAs) : undefined;
    return other ? (other.hostname ?? other.mac ?? other.id) : null;
  }

  /** Counters of the last port scan: only the open ports are listed, the others are counted. */
  summary(s: DeviceServices): Record<string, number> {
    const tcp = s.summary.tcp;
    const udp = s.summary.udp;
    return {
      tcp: tcp?.probed ?? 0,
      udp: udp?.probed ?? 0,
      open: (tcp?.open ?? 0) + (udp?.open ?? 0),
      closed: (tcp?.closed ?? 0) + (udp?.closed ?? 0),
      silent: (tcp?.filtered ?? 0) + (udp?.openFiltered ?? 0) + (tcp?.unknown ?? 0) + (udp?.unknown ?? 0),
    };
  }

  ngOnInit(): void {
    void this.run(async () => this.devices.set(await firstValueFrom(this.api.list(this.homeId()))));
  }

  async open(d: Device): Promise<void> {
    await this.run(async () => this.selected.set(await firstValueFrom(this.api.get(d.id))));
  }

  async classify(d: Device, value: string): Promise<void> {
    await this.run(async () => {
      const updated = await firstValueFrom(this.api.classify(d.id, value || null));
      this.selected.set(updated);
      this.devices.update((list) => list.map((x) => (x.id === updated.id ? updated : x)));
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

import { ChangeDetectionStrategy, Component, OnDestroy, OnInit, computed, inject, input, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { TranslocoPipe } from '@jsverse/transloco';
import { firstValueFrom } from 'rxjs';
import { ApiProblem, toApiProblem } from '../../core/api/api-error';
import { AuthService } from '../../core/auth/auth.service';
import { LocalizedDatePipe } from '../../core/i18n/localized-date.pipe';
import {
  ACTIVE_SCAN_STATUSES,
  DeletedCounts,
  GatewayDevice,
  HomeAssistantInventory,
  OpenPort,
  PortMapping,
  SCAN_PROFILES,
  Scan,
  ScanDevice,
  ScanProfile,
  ScansApi,
} from '../../core/scans/scans.api';
import { PortTableComponent } from './port-table.component';

/** Polling interval of the status of an active scan. */
export const SCAN_POLL_MS = 3000;

/**
 * Manual scans of a home (Milestone 6): start, follow, cancel, history and hosts found.
 * Scans start only from this explicit action: nothing is scheduled.
 */
@Component({
  selector: 'app-scans-page',
  imports: [RouterLink, TranslocoPipe, LocalizedDatePipe, PortTableComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <p><a [routerLink]="['/homes', homeId()]">← {{ 'scans.backToHome' | transloco }}</a></p>
    <section class="card wide">
      <h1>{{ 'scans.title' | transloco }}</h1>
      <p class="muted">{{ 'scans.description' | transloco }}</p>
      @if (problem(); as p) {
        <div class="alert error" role="alert">{{ p.messageKey | transloco }}</div>
      }
      @if (canCreate() && !active()) {
        <label>
          {{ 'scans.profile' | transloco }}
          <select data-testid="scan-profile" [value]="profile()" (change)="chooseProfile($any($event.target).value)"
                  [disabled]="busy()">
            @for (p of profiles; track p) {
              <option [value]="p">{{ 'scans.profiles.' + p | transloco }}</option>
            }
          </select>
        </label>
        <p class="muted small" data-testid="profile-hint">{{ 'scans.profileHint.' + profile() | transloco }}</p>
        <button type="button" class="primary" (click)="start()" [disabled]="busy()" data-testid="start-scan">
          {{ 'scans.start' | transloco }}
        </button>
      }
      @if (active(); as s) {
        <div class="alert warning" role="status" data-testid="active-scan">
          <strong>{{ 'scans.status.' + s.status | transloco }}</strong>
          @if (s.progress?.phase) {
            · <span data-testid="scan-phase">{{ 'scans.phase.' + s.progress!.phase | transloco }}</span>
          }
          @if (s.progress?.percent != null) {
            <progress max="100" [value]="s.progress!.percent"></progress> {{ s.progress!.percent }}%
          }
          · {{ 'scans.devicesFound' | transloco: { count: s.devicesDiscovered } }}
          @if (s.cancelRequestedAt) {
            <span class="muted">{{ 'scans.cancelRequested' | transloco }}</span>
          } @else if (canCreate()) {
            <button type="button" (click)="cancel(s)" [disabled]="busy()" data-testid="cancel-scan">
              {{ 'scans.cancel' | transloco }}
            </button>
          }
        </div>
      }
    </section>

    @if (selected(); as s) {
      <section class="card wide" data-testid="scan-detail">
        <h2>{{ 'scans.detail' | transloco }} · {{ s.requestedAt | appDate: 'short' }}</h2>
        <p>
          <span class="badge">{{ 'scans.profiles.' + s.profile | transloco }}</span>
          <span class="badge" [class.ok]="s.status === 'COMPLETED'" [class.warn]="s.status === 'COMPLETED_WITH_WARNINGS'"
                [class.err]="s.status === 'FAILED'">{{ 'scans.status.' + s.status | transloco }}</span>
          @if (s.failureReason) {
            <span class="muted">{{ 'scans.reason.' + s.failureReason | transloco }}</span>
          }
        </p>
        @for (w of s.warnings; track w) {
          <div class="alert warning" role="status">{{ 'scans.warning.' + w | transloco }}</div>
        }
        <p class="muted">{{ 'scans.devicesNote' | transloco }}</p>
        @if (devices().length === 0) {
          <p class="muted">{{ 'scans.noDevices' | transloco }}</p>
        } @else {
          <table class="list" data-testid="devices">
            <thead>
              <tr>
                <th>{{ 'scans.name' | transloco }}</th>
                <th>{{ 'scans.ip' | transloco }}</th>
                <th>{{ 'scans.mac' | transloco }}</th>
                <th>{{ 'scans.method' | transloco }}</th>
                <th>{{ 'scans.declared' | transloco }}</th>
              </tr>
            </thead>
            <tbody>
              @for (d of devices(); track d.ip) {
                <tr>
                  <td>
                    @if (d.hostname) {
                      <strong>{{ d.hostname }}</strong>
                      <span class="muted"> ({{ 'scans.methods.' + d.hostnames![0].method | transloco }})</span>
                    } @else {
                      —
                    }
                  </td>
                  <td>
                    @for (a of d.addresses ?? [d.ip]; track a) {
                      <div><code>{{ a }}</code></div>
                    }
                  </td>
                  <td><code>{{ d.mac ?? '—' }}</code></td>
                  <td>
                    @for (m of d.methods; track m) {
                      <span class="badge">{{ 'scans.methods.' + m | transloco }}</span>
                    }
                  </td>
                  <td data-testid="declared">
                    @if (declared(d); as info) {
                      <div>{{ info }}</div>
                    }
                    @for (s of services(d); track s) {
                      <span class="badge">{{ s }}</span>
                    }
                    @if (mappings(d); as list) {
                      <div class="alert warning" role="note" data-testid="port-mappings">
                        {{ 'scans.portMappings' | transloco: { count: list.length } }}
                        <ul>
                          @for (m of list; track $index) {
                            <li><code>{{ m.protocol }} {{ m.externalPort }} → {{ m.internalClient }}:{{ m.internalPort }}</code>
                              @if (m.description) { <span class="muted">{{ m.description }}</span> }
                              @if (!m.enabled) { <span class="muted">({{ 'scans.disabled' | transloco }})</span> }
                            </li>
                          }
                        </ul>
                      </div>
                    }
                    @if (selfDeclared(d)) {
                      <div class="muted small">{{ 'scans.selfDeclared' | transloco }}</div>
                    }
                  </td>
                </tr>
              }
            </tbody>
          </table>
        }
        @if (s.profile !== 'DISCOVERY') {
          <h3>{{ 'ports.title' | transloco }}</h3>
          <app-port-table [ports]="ports()" [showIp]="true" />
        }
        @if (homeAssistant(); as ha) {
          <h3>{{ 'integrations.homeAssistant' | transloco }}</h3>
          <div data-testid="home-assistant">
            <p>
              {{ 'integrations.instance' | transloco: { ip: ha.ip, version: ha.version ?? '—', count: ha.deviceCount } }}
              @for (p of protocolList(ha); track p.protocol) {
                <span class="badge">{{ 'integrations.protocol.' + p.protocol | transloco }} {{ p.count }}</span>
              }
            </p>
            @if (!ha.https) {
              <div class="alert warning" role="status">{{ 'integrations.plainHttp' | transloco }}</div>
            }
            @if (ha.truncated) {
              <p class="muted">{{ 'integrations.truncated' | transloco }}</p>
            }
            <table class="list">
              <thead>
                <tr>
                  <th>{{ 'scans.name' | transloco }}</th>
                  <th>{{ 'integrations.model' | transloco }}</th>
                  <th>{{ 'integrations.protocolLabel' | transloco }}</th>
                  <th>{{ 'integrations.matchedIp' | transloco }}</th>
                </tr>
              </thead>
              <tbody>
                @for (d of ha.devices; track $index) {
                  <tr>
                    <td>{{ d.name ?? '—' }}</td>
                    <td>{{ modelOf(d) }}</td>
                    <td>{{ 'integrations.protocol.' + d.protocol | transloco }}</td>
                    <td>{{ d.matchedIp ?? '—' }}</td>
                  </tr>
                }
              </tbody>
            </table>
            <p class="muted">{{ 'integrations.note' | transloco }}</p>
          </div>
        }
      </section>
    }

    <section class="card wide">
      <h2>{{ 'scans.history' | transloco }}</h2>
      @if (history().length === 0) {
        <p class="muted">{{ 'scans.empty' | transloco }}</p>
      } @else {
        <table class="list" data-testid="history">
          <tbody>
            @for (s of history(); track s.id) {
              <tr>
                <td>{{ s.requestedAt | appDate: 'short' }}</td>
                <td>{{ 'scans.profiles.' + s.profile | transloco }}</td>
                <td>{{ 'scans.status.' + s.status | transloco }}</td>
                <td>{{ 'scans.devicesFound' | transloco: { count: s.devicesDiscovered } }}</td>
                <td>
                  <button type="button" (click)="select(s)" [disabled]="busy()">{{ 'scans.show' | transloco }}</button>
                  @if (canDelete() && !isActive(s)) {
                    @if (confirmDelete() === s.id) {
                      <span class="alert error" role="alert">{{ 'scans.deleteWarning' | transloco }}</span>
                      <button type="button" class="danger" [attr.data-testid]="'delete-confirm-' + s.id" (click)="remove(s)" [disabled]="busy()">
                        {{ 'scans.deleteConfirm' | transloco }}</button>
                      <button type="button" (click)="confirmDelete.set(null)" [disabled]="busy()">{{ 'scans.keep' | transloco }}</button>
                    } @else {
                      <button type="button" [attr.data-testid]="'delete-' + s.id" (click)="confirmDelete.set(s.id)" [disabled]="busy()">
                        {{ 'scans.delete' | transloco }}</button>
                    }
                  }
                </td>
              </tr>
            }
          </tbody>
        </table>
      }
      @if (deletedInfo(); as info) {
        <div class="alert success" role="status" data-testid="deleted-info">{{ 'scans.deleted' | transloco: info }}</div>
      }
      @if (canDelete() && history().length > 0 && !active()) {
        <h3>{{ 'scans.clearTitle' | transloco }}</h3>
        <p class="muted small">{{ 'scans.clearHint' | transloco }}</p>
        @if (confirmClear()) {
          <div class="alert error" role="alert">{{ 'scans.clearWarning' | transloco }}</div>
          <button type="button" class="danger" data-testid="clear-confirm" (click)="clearHome()" [disabled]="busy()">
            {{ 'scans.clearConfirm' | transloco }}</button>
          <button type="button" (click)="confirmClear.set(false)" [disabled]="busy()">{{ 'scans.keep' | transloco }}</button>
        } @else {
          <button type="button" data-testid="clear-home" (click)="confirmClear.set(true)" [disabled]="busy()">
            {{ 'scans.clear' | transloco }}</button>
        }
      }
    </section>
  `,
})
export class ScansPage implements OnInit, OnDestroy {
  private readonly api = inject(ScansApi);
  private readonly auth = inject(AuthService);

  /** Route parameter :id (component input binding). */
  readonly homeId = input.required<string>({ alias: 'id' });

  readonly history = signal<Scan[]>([]);
  readonly selected = signal<Scan | null>(null);
  readonly devices = signal<ScanDevice[]>([]);
  readonly ports = signal<OpenPort[]>([]);
  readonly homeAssistant = signal<HomeAssistantInventory | null>(null);
  readonly profiles = SCAN_PROFILES;
  readonly profile = signal<ScanProfile>('DISCOVERY');
  readonly busy = signal(false);
  readonly problem = signal<ApiProblem | null>(null);
  readonly active = computed(() => this.history().find((s) => ACTIVE_SCAN_STATUSES.includes(s.status)) ?? null);

  private timer: ReturnType<typeof setTimeout> | null = null;
  /** Same key until the request succeeds: a double click or a retry cannot start two scans. */
  private pendingKey: string | null = null;

  /** Two-step confirmation: id of the scan being deleted, or the whole inventory. */
  readonly confirmDelete = signal<string | null>(null);
  readonly confirmClear = signal(false);
  readonly deletedInfo = signal<DeletedCounts | null>(null);

  canDelete(): boolean {
    return this.auth.hasPermission('scan:delete');
  }

  isActive(scan: Scan): boolean {
    return ACTIVE_SCAN_STATUSES.includes(scan.status);
  }

  async remove(scan: Scan): Promise<void> {
    await this.run(async () => {
      this.deletedInfo.set(await firstValueFrom(this.api.remove(scan.id)));
      this.confirmDelete.set(null);
      if (this.selected()?.id === scan.id) {
        this.selected.set(null);
      }
      await this.refresh();
    });
  }

  async clearHome(): Promise<void> {
    await this.run(async () => {
      this.deletedInfo.set(await firstValueFrom(this.api.clearHome(this.homeId())));
      this.confirmClear.set(false);
      this.selected.set(null);
      await this.refresh();
    });
  }

  canCreate(): boolean {
    return this.auth.hasPermission('scan:create');
  }

  /** Model, maker and name declared by the device (UPnP, router, mDNS), or null. */
  declared(d: ScanDevice): string | null {
    const values = new Set<string>();
    for (const e of d.evidence ?? []) {
      const x = e.details ?? {};
      const txt = (x['txt'] ?? {}) as Record<string, unknown>;
      for (const v of [x['friendlyName'], x['manufacturer'], x['modelName'], txt['ty'], txt['md'], txt['model']]) {
        if (typeof v === 'string' && v.trim()) {
          values.add(v.trim());
        }
      }
    }
    return values.size ? [...values].join(' · ') : null;
  }

  /** Service types announced over mDNS. */
  services(d: ScanDevice): string[] {
    const out = new Set<string>();
    for (const e of d.evidence ?? []) {
      for (const s of (e.details?.['services'] as { type: string; port?: number }[] | undefined) ?? []) {
        out.add(s.port ? `${s.type}:${s.port}` : s.type);
      }
    }
    return [...out];
  }

  /** Port mappings declared by an Internet gateway (UPnP IGD), or null. */
  mappings(d: ScanDevice): PortMapping[] | null {
    const list = d.evidence?.flatMap((e) => (e.details?.['portMappings'] as PortMapping[] | undefined) ?? []) ?? [];
    return list.length ? list : null;
  }

  selfDeclared(d: ScanDevice): boolean {
    return (d.evidence ?? []).some((e) => e.details?.['selfDeclared'] === true);
  }

  ngOnInit(): void {
    void this.refresh();
  }

  ngOnDestroy(): void {
    this.stopPolling();
  }

  /** A different profile is a different request: it gets a new idempotency key. */
  chooseProfile(value: ScanProfile): void {
    if (value !== this.profile()) {
      this.profile.set(value);
      this.pendingKey = null;
    }
  }

  async start(): Promise<void> {
    this.pendingKey ??= crypto.randomUUID();
    await this.run(async () => {
      await firstValueFrom(this.api.request(this.homeId(), this.pendingKey!, this.profile()));
      this.pendingKey = null;
      await this.refresh();
    });
  }

  async cancel(scan: Scan): Promise<void> {
    await this.run(async () => {
      await firstValueFrom(this.api.cancel(scan.id));
      await this.refresh();
    });
  }

  async select(scan: Scan): Promise<void> {
    await this.run(async () => {
      this.selected.set(await firstValueFrom(this.api.get(scan.id)));
      this.devices.set(await firstValueFrom(this.api.devices(scan.id)));
      this.ports.set(scan.profile === 'DISCOVERY' ? [] : await firstValueFrom(this.api.ports(scan.id)));
      this.homeAssistant.set((await firstValueFrom(this.api.integrations(scan.id))).homeAssistant);
    });
  }

  modelOf(d: GatewayDevice): string {
    return [d.manufacturer, d.model, d.swVersion].filter((v) => !!v).join(' · ') || '—';
  }

  protocolList(ha: HomeAssistantInventory): { protocol: string; count: number }[] {
    return Object.entries(ha.protocols).map(([protocol, count]) => ({ protocol, count: count ?? 0 }));
  }

  /** Reloads the history; while a scan is active polls it, and shows its results when it ends. */
  async refresh(): Promise<void> {
    this.stopPolling();
    const wasActive = this.active();
    try {
      this.history.set(await firstValueFrom(this.api.history(this.homeId())));
    } catch (error) {
      this.problem.set(toApiProblem(error));
      return;
    }
    if (this.active()) {
      this.timer = setTimeout(() => void this.refresh(), SCAN_POLL_MS);
    } else if (wasActive) {
      const finished = this.history().find((s) => s.id === wasActive.id);
      if (finished) {
        await this.select(finished);
      }
    }
  }

  private stopPolling(): void {
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = null;
    }
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

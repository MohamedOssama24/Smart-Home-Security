import { ChangeDetectionStrategy, Component, OnInit, computed, inject, input, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { TranslocoPipe } from '@jsverse/transloco';
import { firstValueFrom } from 'rxjs';
import { ApiProblem, toApiProblem } from '../../core/api/api-error';
import { AuthService } from '../../core/auth/auth.service';
import { Device, DevicesApi } from '../../core/devices/devices.api';
import { HomesApi, Network } from '../../core/homes/homes.api';
import { LocalizedDatePipe } from '../../core/i18n/localized-date.pipe';
import { RiskApi, RiskSnapshot } from '../../core/risk/risk.api';
import { MapGroup, MapNode, layoutNetworkMap } from './network-layout';

/**
 * Network map of a home (Milestone 12): for each authorized network the router at the center
 * and the inventory devices around it, colored by the points they take off the last computed
 * score; devices with a UPnP port mapping are linked to the Internet. A table repeats the same
 * data (keyboard, screen readers, small screens). The risk part needs finding:read: without
 * it the map shows the devices only.
 */
@Component({
  selector: 'app-network-map-page',
  imports: [RouterLink, TranslocoPipe, LocalizedDatePipe],
  changeDetection: ChangeDetectionStrategy.OnPush,
  styles: [`
    svg { width: 100%; height: auto; max-height: 75vh; display: block; }
    .link { stroke: var(--border); stroke-width: 2; }
    .exposure { stroke: var(--err-fg); stroke-width: 2; stroke-dasharray: 6 4; }
    .node circle { stroke-width: 2; cursor: pointer; }
    .node:focus { outline: none; }
    .node:focus circle, .node.selected circle { stroke-width: 4; }
    .none circle { fill: var(--ok-bg); stroke: var(--ok-fg); }
    .low circle { fill: var(--warn-bg); stroke: var(--warn-fg); }
    .high circle { fill: var(--err-bg); stroke: var(--err-fg); }
    .unknown circle, .internet circle, .placeholder circle { fill: var(--surface); stroke: var(--text-muted); }
    .placeholder circle { stroke-dasharray: 4 3; }
    text { fill: var(--text); font-size: 12px; text-anchor: middle; pointer-events: none; }
    .glyph { font-size: 15px; font-weight: 700; }
    .legend { display: flex; gap: 12px; flex-wrap: wrap; font-size: .85rem; }
    .linklike { border: 0; background: none; padding: 0; color: var(--primary); text-decoration: underline; }
  `],
  template: `
    <p><a [routerLink]="['/homes', homeId()]">← {{ 'risk.backToHome' | transloco }}</a></p>
    <section class="card wide">
      <h1>{{ 'networkMap.title' | transloco }}</h1>
      <p class="muted">{{ 'networkMap.description' | transloco }}</p>
      @if (problem(); as p) {
        <div class="alert error" role="alert">{{ p.messageKey | transloco }}</div>
      }
      @if (loaded()) {
        @if (groups().length === 0) {
          <p class="muted" data-testid="no-devices">{{ 'networkMap.noDevices' | transloco }}</p>
        } @else {
          <div class="legend" data-testid="legend">
            @if (riskSnapshot(); as s) {
              <span><span class="badge ok">●</span> {{ 'networkMap.legend.none' | transloco }}</span>
              <span><span class="badge warn">●</span> {{ 'networkMap.legend.low' | transloco }}</span>
              <span><span class="badge err">●</span> {{ 'networkMap.legend.high' | transloco }}</span>
              <span class="muted">{{ 'networkMap.legend.score' | transloco: { score: s.score } }} ({{ s.computedAt | appDate: 'short' }})</span>
            } @else {
              <span class="muted" data-testid="no-risk">{{ 'networkMap.noRisk' | transloco }}</span>
            }
            <span><span class="badge err">- -</span> {{ 'networkMap.legend.exposed' | transloco }}</span>
          </div>
        }
      }
    </section>

    @for (g of groups(); track g.network?.id ?? 'other') {
      <section class="card wide" [attr.data-testid]="'group-' + (g.network?.cidr ?? 'other')">
        <h2>
          @if (g.network; as n) { {{ n.name }} <span class="muted small">{{ n.cidr }}</span> }
          @else { {{ 'networkMap.otherDevices' | transloco }} }
        </h2>
        <svg [attr.viewBox]="'0 0 ' + g.width + ' ' + g.height" role="group"
             [attr.aria-label]="(g.network?.name ?? ('networkMap.otherDevices' | transloco))">
          @if (g.network) {
            <line class="link" [attr.x1]="g.internet.x" [attr.y1]="g.internet.y" [attr.x2]="g.center.x" [attr.y2]="g.center.y" />
            <g class="internet"><circle [attr.cx]="g.internet.x" [attr.cy]="g.internet.y" r="22" />
              <text [attr.x]="g.internet.x" [attr.y]="g.internet.y + 5" class="glyph">🌐</text></g>
          }
          @for (n of g.nodes; track n.device.id) {
            @if (g.network) {
              <line class="link" [attr.x1]="g.center.x" [attr.y1]="g.center.y" [attr.x2]="n.x" [attr.y2]="n.y" />
            }
            @if (n.exposed && g.network) {
              <path class="exposure" fill="none" [attr.d]="exposurePath(g, n)" />
            }
          }
          @if (!g.gateway && g.network) {
            <g class="placeholder"><circle [attr.cx]="g.center.x" [attr.cy]="g.center.y" r="30" />
              <text [attr.x]="g.center.x" [attr.y]="g.center.y + 46">{{ 'networkMap.routerUnknown' | transloco }}</text></g>
          }
          @for (n of drawn(g); track n.device.id) {
            <g class="node" [class]="n.level" [class.selected]="selected()?.device?.id === n.device.id" tabindex="0"
               role="button" [attr.aria-label]="label(n)" [attr.data-testid]="'node-' + n.device.id"
               (click)="select(n)" (keydown.enter)="select(n)" (keydown.space)="select(n); $event.preventDefault()">
              <circle [attr.cx]="n.x" [attr.cy]="n.y" [attr.r]="radius(g, n)" />
              <text [attr.x]="n.x" [attr.y]="n.y + 5" class="glyph">{{ glyph(n) }}</text>
              <text [attr.x]="n.x" [attr.y]="n.y + radius(g, n) + 16">{{ short(n) }}</text>
            </g>
          }
        </svg>
      </section>
    }

    @if (selected(); as n) {
      <section class="card wide" data-testid="details" aria-live="polite">
        <h2>{{ name(n) }}</h2>
        <dl class="facts">
          <dt>IP</dt><dd>{{ n.device.ip ?? '—' }}</dd>
          <dt>MAC</dt><dd>{{ n.device.mac ?? '—' }}</dd>
          <dt>{{ 'networkMap.category' | transloco }}</dt><dd>{{ 'devices.categories.' + n.device.category | transloco }}</dd>
          @if (n.device.manufacturer) { <dt>{{ 'networkMap.manufacturer' | transloco }}</dt><dd>{{ n.device.manufacturer }}</dd> }
          @if (n.risk; as r) {
            <dt>{{ 'networkMap.points' | transloco }}</dt><dd data-testid="points">−{{ r.applied }}
              @if (r.capped) { <span class="muted small">({{ 'risk.cappedDevice' | transloco: { raw: r.raw } }})</span> }</dd>
            <dt>{{ 'networkMap.findings' | transloco }}</dt><dd>{{ r.findings }}</dd>
          } @else if (riskSnapshot()) {
            <dt>{{ 'networkMap.points' | transloco }}</dt><dd data-testid="points">0</dd>
          }
          @if (n.exposed) { <dt></dt><dd><span class="badge err">{{ 'risk.exposed' | transloco }}</span></dd> }
          <dt>{{ 'networkMap.lastSeen' | transloco }}</dt><dd>{{ n.device.lastSeenAt | appDate: 'short' }}</dd>
        </dl>
        <p class="actions small">
          <a [routerLink]="['/homes', homeId(), 'devices']">{{ 'devices.title' | transloco }} →</a>
          @if (riskSnapshot()) { <a [routerLink]="['/homes', homeId(), 'findings']">{{ 'findings.title' | transloco }} →</a> }
        </p>
      </section>
    }

    @if (allNodes().length) {
      <section class="card wide">
        <h2>{{ 'networkMap.tableTitle' | transloco }}</h2>
        <table class="list" data-testid="device-table">
          <thead><tr>
            <th>{{ 'networkMap.device' | transloco }}</th><th>IP</th><th>{{ 'networkMap.category' | transloco }}</th>
            <th>{{ 'networkMap.points' | transloco }}</th><th>{{ 'networkMap.network' | transloco }}</th>
          </tr></thead>
          <tbody>
            @for (row of allNodes(); track row.node.device.id) {
              <tr>
                <td><button type="button" class="linklike" (click)="select(row.node)">{{ name(row.node) }}</button>
                  @if (row.node.exposed) { <span class="badge err">{{ 'risk.exposed' | transloco }}</span> }</td>
                <td>{{ row.node.device.ip }}</td>
                <td>{{ 'devices.categories.' + row.node.device.category | transloco }}</td>
                <td>{{ riskSnapshot() ? points(row.node) : '—' }}</td>
                <td>{{ row.network }}</td>
              </tr>
            }
          </tbody>
        </table>
        <p class="muted small">{{ 'networkMap.logicalNote' | transloco }}</p>
      </section>
    }
  `,
})
export class NetworkMapPage implements OnInit {
  readonly homeId = input.required<string>({ alias: 'id' });
  private readonly devicesApi = inject(DevicesApi);
  private readonly homesApi = inject(HomesApi);
  private readonly riskApi = inject(RiskApi);
  private readonly auth = inject(AuthService);

  readonly devices = signal<Device[]>([]);
  readonly networks = signal<Network[]>([]);
  /** Last snapshot with a score (the current one has none after a Discovery scan). */
  readonly riskSnapshot = signal<RiskSnapshot | null>(null);
  readonly loaded = signal(false);
  readonly problem = signal<ApiProblem | null>(null);
  readonly selected = signal<MapNode | null>(null);

  readonly groups = computed(() =>
    layoutNetworkMap(this.devices(), this.networks(), this.riskSnapshot()?.breakdown.devices ?? (this.riskSnapshot() ? [] : null)),
  );

  readonly allNodes = computed(() =>
    this.groups().flatMap((g) =>
      [...(g.gateway ? [g.gateway] : []), ...g.nodes].map((node) => ({ node, network: g.network?.cidr ?? '—' })),
    ),
  );

  async ngOnInit(): Promise<void> {
    try {
      const [devices, networks] = await Promise.all([
        firstValueFrom(this.devicesApi.list(this.homeId())),
        firstValueFrom(this.homesApi.networks(this.homeId())),
      ]);
      this.devices.set(devices);
      this.networks.set(networks);
      if (this.auth.hasPermission('finding:read')) {
        const risk = await firstValueFrom(this.riskApi.current(this.homeId()));
        this.riskSnapshot.set(risk.lastScored);
      }
    } catch (e) {
      this.problem.set(toApiProblem(e));
    } finally {
      this.loaded.set(true);
    }
  }

  /** Router first, then the other devices (drawn over the links). */
  drawn(g: MapGroup): MapNode[] {
    return g.gateway ? [g.gateway, ...g.nodes] : g.nodes;
  }

  radius(g: MapGroup, n: MapNode): number {
    return n === g.gateway ? 30 : 22;
  }

  /** Curved link to the Internet, bent sideways so it does not run over the router. */
  exposurePath(g: MapGroup, n: MapNode): string {
    const side = n.x >= g.center.x ? 1 : -1;
    const cx = Math.min(g.width - 10, Math.max(10, g.center.x + side * (Math.abs(n.x - g.center.x) + 120)));
    const cy = (n.y + g.internet.y) / 2;
    return `M ${n.x} ${n.y} Q ${cx} ${cy} ${g.internet.x} ${g.internet.y}`;
  }

  points(n: MapNode): string {
    const applied = n.risk?.applied ?? 0;
    return applied > 0 ? `−${applied}` : '0';
  }

  select(node: MapNode): void {
    this.selected.set(node);
  }

  name(n: MapNode): string {
    return n.device.hostname || n.device.model || n.device.manufacturer || n.device.ip || n.device.id;
  }

  short(n: MapNode): string {
    const v = this.name(n);
    return v.length > 13 ? `${v.slice(0, 12)}…` : v;
  }

  label(n: MapNode): string {
    const points = n.risk ? ` −${n.risk.applied}` : '';
    return `${this.name(n)} ${n.device.ip ?? ''}${points}${n.exposed ? ' Internet' : ''}`;
  }

  glyph(n: MapNode): string {
    return GLYPHS[n.device.category] ?? '?';
  }
}

const GLYPHS: Record<string, string> = {
  ROUTER: 'R', IP_CAMERA: 'C', SMART_TV: 'TV', SMARTPHONE: 'P', TABLET: 'T', LAPTOP: 'L', DESKTOP: 'D',
  PRINTER: 'S', NAS: 'N', SMART_PLUG: 'PL', SMART_SPEAKER: 'SP', IOT: 'I', UNKNOWN_DEVICE: '?',
};

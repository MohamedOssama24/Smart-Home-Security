import { LocalizedDatePipe } from '../../core/i18n/localized-date.pipe';
import { ChangeDetectionStrategy, Component, OnInit, inject, input, signal } from '@angular/core';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { Router, RouterLink } from '@angular/router';
import { TranslocoPipe } from '@jsverse/transloco';
import { firstValueFrom } from 'rxjs';
import { ApiProblem, toApiProblem } from '../../core/api/api-error';
import { AuthService } from '../../core/auth/auth.service';
import {
  ATTESTATION_VERSION,
  Agent,
  AgentEvent,
  CreatedEnrollmentToken,
  EnrollmentToken,
  Home,
  HomesApi,
  NETWORK_KINDS,
  Network,
  NetworkKind,
} from '../../core/homes/homes.api';

@Component({
  selector: 'app-home-detail-page',
  imports: [ReactiveFormsModule, RouterLink, TranslocoPipe, LocalizedDatePipe],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <p><a routerLink="/homes">← {{ 'homes.title' | transloco }}</a></p>
    @if (problem(); as p) {
      <div class="card wide"><div class="alert error" role="alert">{{ p.messageKey | transloco }}</div></div>
    }
    @if (home(); as h) {
      <section class="card wide">
        <h1>{{ h.name }}</h1>
        @if (h.address) {
          <p class="muted">{{ h.address }}</p>
        }
        <p class="muted">{{ 'homes.fields.timezone' | transloco }}: {{ h.timezone }}</p>
        @if (canReadScans()) {
          <p><a [routerLink]="['/homes', h.id, 'scans']" data-testid="scans-link">{{ 'scans.title' | transloco }} →</a></p>
        }
        @if (canReadDevices()) {
          <p><a [routerLink]="['/homes', h.id, 'devices']" data-testid="devices-link">{{ 'devices.title' | transloco }} →</a></p>
          <p><a [routerLink]="['/homes', h.id, 'network-map']" data-testid="network-map-link">{{ 'networkMap.title' | transloco }} →</a></p>
        }
        @if (canReadFindings()) {
          <p><a [routerLink]="['/homes', h.id, 'findings']" data-testid="findings-link">{{ 'findings.title' | transloco }} →</a></p>
          <p><a [routerLink]="['/homes', h.id, 'risk']" data-testid="risk-link">{{ 'risk.title' | transloco }} →</a></p>
          <p><a [routerLink]="['/homes', h.id, 'vulnerabilities']" data-testid="vulnerabilities-link">{{ 'vulnerabilities.title' | transloco }} →</a></p>
          <p><a [routerLink]="['/homes', h.id, 'reports']" data-testid="reports-link">{{ 'reports.title' | transloco }} →</a></p>
          <p><a [routerLink]="['/homes', h.id, 'assistant']" data-testid="assistant-link">{{ 'assistant.title' | transloco }} →</a></p>
        }
        @if (canWrite()) {
          @if (editing()) {
            <form [formGroup]="homeForm" (ngSubmit)="saveHome(h)" novalidate data-testid="home-form">
              <div class="field">
                <label for="editName">{{ 'homes.fields.name' | transloco }}</label>
                <input id="editName" formControlName="name" />
              </div>
              <div class="field">
                <label for="editAddress">{{ 'homes.fields.address' | transloco }}</label>
                <input id="editAddress" formControlName="address" />
              </div>
              <div class="field">
                <label for="editTimezone">{{ 'homes.fields.timezone' | transloco }}</label>
                <input id="editTimezone" formControlName="timezone" placeholder="Europe/Rome" />
              </div>
              <div class="actions">
                <button class="primary" type="submit" [disabled]="busy() || homeForm.invalid">
                  {{ 'common.save' | transloco }}
                </button>
                <button type="button" (click)="editing.set(false)">{{ 'common.cancel' | transloco }}</button>
              </div>
            </form>
          } @else {
            <div class="actions">
              <button type="button" (click)="startEdit(h)" [disabled]="busy()" data-testid="edit-home">
                {{ 'common.edit' | transloco }}
              </button>
              @if (confirmingArchive()) {
                <span class="muted" role="status">{{ 'homes.archiveConfirm' | transloco }}</span>
                <button type="button" class="danger" (click)="archiveHome(h)" [disabled]="busy()"
                        data-testid="confirm-archive-home">
                  {{ 'common.confirmArchive' | transloco }}
                </button>
                <button type="button" (click)="confirmingArchive.set(false)">{{ 'common.cancel' | transloco }}</button>
              } @else {
                <button type="button" class="danger" (click)="confirmingArchive.set(true)" [disabled]="busy()"
                        data-testid="archive-home">
                  {{ 'common.archive' | transloco }}
                </button>
              }
            </div>
          }
        }
      </section>

      <section class="card wide" data-testid="networks">
        <h2>{{ 'networks.title' | transloco }}</h2>
        <p class="muted">{{ 'networks.description' | transloco }}</p>
        @if (networks().length === 0) {
          <p class="muted">{{ 'networks.empty' | transloco }}</p>
        } @else {
          <table class="list">
            <thead>
              <tr>
                <th>{{ 'networks.name' | transloco }}</th>
                <th>{{ 'networks.cidr' | transloco }}</th>
                <th>{{ 'networks.authorization' | transloco }}</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              @for (network of networks(); track network.id) {
                <tr [attr.data-network]="network.cidr">
                  <td>{{ network.name }}<br /><span class="muted">{{ 'networks.kind.' + network.kind | transloco }}</span></td>
                  <td><code>{{ network.cidr }}</code></td>
                  <td>
                    @if (network.authorization; as a) {
                      <span class="badge ok">{{ 'networks.authorized' | transloco }}</span>
                      <br /><span class="muted">{{ a.authorizedAt | appDate: 'short' }}</span>
                    } @else {
                      <span class="badge">{{ 'networks.notAuthorized' | transloco }}</span>
                    }
                  </td>
                  <td>
                    <div class="actions">
                      @if (canAuthorize()) {
                        @if (network.authorized) {
                          <button type="button" (click)="revokeAuthorization(network)" [disabled]="busy()"
                                  data-testid="revoke-authorization">
                            {{ 'networks.revoke' | transloco }}
                          </button>
                        } @else {
                          <button type="button" (click)="startAuthorize(network)" [disabled]="busy()"
                                  data-testid="authorize">
                            {{ 'networks.authorize' | transloco }}
                          </button>
                        }
                      }
                      @if (canManageNetworks()) {
                        @if (confirmingNetworkDelete() === network.id) {
                          <button type="button" class="danger" (click)="deleteNetwork(network)" [disabled]="busy()"
                                  data-testid="confirm-delete-network">
                            {{ 'networks.deleteConfirm' | transloco }}
                          </button>
                          <button type="button" (click)="confirmingNetworkDelete.set(null)">
                            {{ 'common.cancel' | transloco }}
                          </button>
                        } @else {
                          <button type="button" class="danger" (click)="confirmingNetworkDelete.set(network.id)"
                                  [disabled]="busy()" data-testid="delete-network">
                            {{ 'common.delete' | transloco }}
                          </button>
                        }
                      }
                    </div>
                  </td>
                </tr>
                @if (authorizing() === network.id) {
                  <tr>
                    <td colspan="4">
                      <!-- the attestation is a deliberate statement by the user: never pre-checked -->
                      <div class="alert warning" data-testid="attestation">
                        <label>
                          <input type="checkbox" [checked]="attested()" (change)="attested.set($any($event.target).checked)"
                                 data-testid="attestation-checkbox" />
                          {{ 'networks.attestation.v' + attestationVersion | transloco: { cidr: network.cidr } }}
                        </label>
                        <p class="muted">{{ 'networks.attestationNote' | transloco }}</p>
                        <div class="actions">
                          <button type="button" class="primary" (click)="authorize(network)"
                                  [disabled]="busy() || !attested()" data-testid="confirm-authorize">
                            {{ 'networks.authorizeConfirm' | transloco }}
                          </button>
                          <button type="button" (click)="authorizing.set(null)">{{ 'common.cancel' | transloco }}</button>
                        </div>
                      </div>
                    </td>
                  </tr>
                }
              }
            </tbody>
          </table>
        }
        @if (canManageNetworks()) {
          <h3>{{ 'networks.add' | transloco }}</h3>
          <form [formGroup]="networkForm" (ngSubmit)="addNetwork()" novalidate>
            <div class="field">
              <label for="networkName">{{ 'networks.name' | transloco }}</label>
              <input id="networkName" formControlName="name" />
            </div>
            <div class="field">
              <label for="networkCidr">{{ 'networks.cidr' | transloco }}</label>
              <input id="networkCidr" formControlName="cidr" placeholder="192.168.1.0/24" autocomplete="off" />
              <span class="hint">{{ 'networks.cidrHint' | transloco }}</span>
            </div>
            <div class="field">
              <label for="networkKind">{{ 'networks.kindLabel' | transloco }}</label>
              <select id="networkKind" formControlName="kind">
                @for (kind of networkKinds; track kind) {
                  <option [value]="kind">{{ 'networks.kind.' + kind | transloco }}</option>
                }
              </select>
            </div>
            <button class="primary" type="submit" [disabled]="busy() || networkForm.invalid">
              {{ 'networks.addSubmit' | transloco }}
            </button>
          </form>
        }
      </section>

      <section class="card wide">
        <h2>{{ 'agents.title' | transloco }}</h2>
        @if (agents().length === 0) {
          <p class="muted">{{ 'agents.empty' | transloco }}</p>
        } @else {
          <table class="list" data-testid="agents">
            <thead>
              <tr>
                <th>{{ 'agents.name' | transloco }}</th>
                <th>{{ 'agents.system' | transloco }}</th>
                <th>{{ 'agents.lastSeen' | transloco }}</th>
                <th>{{ 'agents.status' | transloco }}</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              @for (agent of agents(); track agent.id) {
                <tr>
                  <td>{{ agent.name }}<br /><span class="muted">{{ agent.hostname }}</span></td>
                  <td>{{ agent.os }}/{{ agent.arch }} · {{ agent.agentVersion }}</td>
                  <td>{{ agent.lastHeartbeatAt ?? agent.lastSeenAt | appDate: 'short' }}</td>
                  <td>
                    <span class="badge" data-testid="connectivity"
                          [class.ok]="agent.connectivity === 'ONLINE'"
                          [class.warn]="agent.connectivity === 'STALE'"
                          [class.err]="agent.connectivity === 'OFFLINE' || agent.connectivity === 'REVOKED'">
                      {{ 'agents.connectivity.' + agent.connectivity | transloco }}
                    </span>
                  </td>
                  <td>
                    <button type="button" (click)="toggleDiagnosis(agent)" [attr.aria-expanded]="expanded() === agent.id"
                            data-testid="diagnosis-toggle">
                      {{ (expanded() === agent.id ? 'agents.diagnosis.hide' : 'agents.diagnosis.show') | transloco }}
                    </button>
                    @if (agent.status === 'ACTIVE' && canRevoke()) {
                      @if (confirmingRevoke() === agent.id) {
                        <!-- revocation cannot be undone: the agent must be enrolled again -->
                        <div class="actions">
                          <span class="muted" role="status">{{ 'agents.revokeConfirm' | transloco }}</span>
                          <button type="button" class="danger" (click)="revokeAgent(agent)" [disabled]="busy()"
                                  data-testid="confirm-revoke">
                            {{ 'agents.revokeConfirmYes' | transloco }}
                          </button>
                          <button type="button" (click)="confirmingRevoke.set(null)" [disabled]="busy()">
                            {{ 'agents.revokeCancel' | transloco }}
                          </button>
                        </div>
                      } @else {
                        <button type="button" class="danger" (click)="confirmingRevoke.set(agent.id)" [disabled]="busy()"
                                data-testid="revoke">
                          {{ 'agents.revoke' | transloco }}
                        </button>
                      }
                    }
                  </td>
                </tr>
                @if (expanded() === agent.id) {
                  <tr>
                    <td colspan="5" data-testid="diagnosis">
                      @if (agent.capabilities; as caps) {
                        <dl class="facts">
                          <dt>{{ 'agents.diagnosis.arp' | transloco }}</dt>
                          <dd>{{ 'agents.technique.' + caps.arp | transloco }}</dd>
                          <dt>{{ 'agents.diagnosis.icmp' | transloco }}</dt>
                          <dd>{{ 'agents.technique.' + caps.icmp | transloco }}</dd>
                          <dt>{{ 'agents.diagnosis.privileged' | transloco }}</dt>
                          <dd>{{ (caps.privileged ? 'common.yes' : 'common.no') | transloco }}</dd>
                          <dt>{{ 'agents.diagnosis.queue' | transloco }}</dt>
                          <dd>{{ agent.queueDepth ?? 0 }}</dd>
                          <dt>{{ 'agents.diagnosis.router' | transloco }}</dt>
                          <dd>{{ caps.routerIntegrations?.length ? caps.routerIntegrations!.join(', ') : ('agents.diagnosis.noRouter' | transloco) }}</dd>
                        </dl>
                        @for (warning of caps.warnings; track warning) {
                          <div class="alert warning" role="status">{{ 'agents.warning.' + warning | transloco }}</div>
                        }
                        <h3>{{ 'agents.diagnosis.interfaces' | transloco }}</h3>
                        @if (agent.interfaces?.length) {
                          <ul>
                            @for (iface of agent.interfaces; track iface.name) {
                              <li><strong>{{ iface.name }}</strong> {{ iface.addresses.join(', ') }}</li>
                            }
                          </ul>
                        } @else {
                          <p class="muted">{{ 'agents.diagnosis.noInterfaces' | transloco }}</p>
                        }
                      } @else {
                        <p class="muted">{{ 'agents.diagnosis.noHeartbeat' | transloco }}</p>
                      }
                      @if (agent.lastError) {
                        <p class="muted">{{ 'agents.diagnosis.lastError' | transloco }}: <code>{{ agent.lastError }}</code></p>
                      }
                      <h3>{{ 'agents.diagnosis.events' | transloco }}</h3>
                      @if (events().length) {
                        <ul data-testid="agent-events">
                          @for (event of events(); track event.id) {
                            <li>{{ event.occurredAt | appDate: 'short' }} · {{ 'agents.event.' + event.type | transloco }}</li>
                          }
                        </ul>
                      } @else {
                        <p class="muted">{{ 'agents.diagnosis.noEvents' | transloco }}</p>
                      }
                    </td>
                  </tr>
                }
              }
            </tbody>
          </table>
        }
      </section>

      @if (canEnroll()) {
        <section class="card wide">
          <h2>{{ 'agents.enroll.title' | transloco }}</h2>
          <p class="muted">{{ 'agents.enroll.description' | transloco }}</p>
          @if (created(); as c) {
            <div class="alert warning" role="status" data-testid="enrollment-token">
              {{ 'agents.enroll.showOnce' | transloco: { expires: (c.expiresAt | appDate: 'shortTime') } }}
              <code class="secret">{{ c.token }}</code>
              <span class="muted">{{ 'agents.enroll.command' | transloco }}</span>
              <code class="secret">shsc-agent enroll --api {{ origin }} --token-file token.txt</code>
              <span class="muted">{{ 'agents.enroll.service' | transloco }}</span>
              <code class="secret">shsc-agent service install</code>
            </div>
          }
          <button type="button" class="primary" (click)="createToken()" [disabled]="busy()">
            {{ 'agents.enroll.create' | transloco }}
          </button>

          @if (tokens().length) {
            <table class="list" style="margin-top: 16px">
              <thead>
                <tr>
                  <th>{{ 'agents.enroll.createdAt' | transloco }}</th>
                  <th>{{ 'agents.enroll.expiresAt' | transloco }}</th>
                  <th>{{ 'agents.status' | transloco }}</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                @for (token of tokens(); track token.id) {
                  <tr>
                    <td>{{ token.createdAt | appDate: 'short' }}</td>
                    <td>{{ token.expiresAt | appDate: 'short' }}</td>
                    <td><span class="badge">{{ 'agents.tokenState.' + token.state | transloco }}</span></td>
                    <td>
                      @if (token.state === 'ACTIVE' && canRevoke()) {
                        <button type="button" (click)="revokeToken(token)" [disabled]="busy()">
                          {{ 'agents.enroll.revoke' | transloco }}
                        </button>
                      }
                    </td>
                  </tr>
                }
              </tbody>
            </table>
          }
        </section>
      }
    }
  `,
})
export class HomeDetailPage implements OnInit {
  private readonly api = inject(HomesApi);
  private readonly auth = inject(AuthService);

  /** Route parameter (component input binding). */
  readonly id = input.required<string>();

  readonly origin = typeof location === 'undefined' ? '' : location.origin;
  readonly home = signal<Home | null>(null);
  readonly agents = signal<Agent[]>([]);
  readonly tokens = signal<EnrollmentToken[]>([]);
  readonly created = signal<CreatedEnrollmentToken | null>(null);
  readonly busy = signal(false);
  /** Agent whose revocation is waiting for the second click. */
  readonly confirmingRevoke = signal<string | null>(null);
  /** Agent whose self-diagnosis is shown, with its recent events. */
  readonly expanded = signal<string | null>(null);
  readonly events = signal<AgentEvent[]>([]);
  readonly problem = signal<ApiProblem | null>(null);

  readonly networks = signal<Network[]>([]);
  readonly networkKinds = NETWORK_KINDS;
  readonly attestationVersion = ATTESTATION_VERSION;
  /** Network whose attestation is open, and whether the user ticked it (never pre-checked). */
  readonly authorizing = signal<string | null>(null);
  readonly attested = signal(false);
  readonly confirmingNetworkDelete = signal<string | null>(null);
  readonly editing = signal(false);
  readonly confirmingArchive = signal(false);

  private readonly router = inject(Router);
  private readonly fb = inject(FormBuilder).nonNullable;
  readonly homeForm = this.fb.group({
    name: ['', [Validators.required, Validators.maxLength(100)]],
    address: ['', [Validators.maxLength(300)]],
    timezone: ['', [Validators.maxLength(64)]],
  });
  readonly networkForm = this.fb.group({
    name: ['', [Validators.required, Validators.maxLength(100)]],
    cidr: ['', [Validators.required, Validators.maxLength(64)]],
    kind: ['WIFI' as NetworkKind],
  });

  canEnroll(): boolean {
    return this.auth.hasPermission('agent:enroll');
  }

  canRevoke(): boolean {
    return this.auth.hasPermission('agent:revoke');
  }

  /** UI hints only: the backend checks the permission on this home. */
  canWrite(): boolean {
    return this.auth.hasPermission('home:write');
  }

  canReadScans(): boolean {
    return this.auth.hasPermission('scan:read');
  }

  canReadDevices(): boolean {
    return this.auth.hasPermission('device:read');
  }

  canReadFindings(): boolean {
    return this.auth.hasPermission('finding:read');
  }

  canManageNetworks(): boolean {
    return this.auth.hasPermission('network:manage');
  }

  canAuthorize(): boolean {
    return this.auth.hasPermission('network:authorize');
  }

  ngOnInit(): void {
    void this.load();
  }

  async load(): Promise<void> {
    try {
      this.home.set(await firstValueFrom(this.api.get(this.id())));
      this.agents.set(await firstValueFrom(this.api.agents(this.id())));
      if (this.canEnroll()) {
        this.tokens.set(await firstValueFrom(this.api.enrollmentTokens(this.id())));
      }
      this.networks.set(await firstValueFrom(this.api.networks(this.id())));
    } catch (error) {
      this.problem.set(toApiProblem(error));
    }
  }

  startEdit(home: Home): void {
    this.homeForm.setValue({ name: home.name, address: home.address ?? '', timezone: home.timezone });
    this.editing.set(true);
  }

  async saveHome(home: Home): Promise<void> {
    if (this.homeForm.invalid) {
      return;
    }
    const value = this.homeForm.getRawValue();
    await this.run(async () => {
      // PUT replaces every editable field: the customer is sent unchanged
      this.home.set(
        await firstValueFrom(
          this.api.update(home.id, {
            name: value.name.trim(),
            customerId: home.customerId,
            address: value.address.trim() || null,
            timezone: value.timezone.trim() || null,
          }),
        ),
      );
      this.editing.set(false);
    });
  }

  async archiveHome(home: Home): Promise<void> {
    await this.run(async () => {
      await firstValueFrom(this.api.archive(home.id));
      this.confirmingArchive.set(false);
      await this.router.navigateByUrl('/homes');
    });
  }

  async addNetwork(): Promise<void> {
    if (this.networkForm.invalid) {
      return;
    }
    const value = this.networkForm.getRawValue();
    await this.run(async () => {
      await firstValueFrom(
        this.api.createNetwork(this.id(), { name: value.name.trim(), cidr: value.cidr.trim(), kind: value.kind }),
      );
      this.networkForm.reset();
      await this.reloadNetworks();
    });
  }

  startAuthorize(network: Network): void {
    this.attested.set(false);
    this.authorizing.set(network.id);
  }

  async authorize(network: Network): Promise<void> {
    if (!this.attested()) {
      return;
    }
    await this.run(async () => {
      await firstValueFrom(this.api.authorizeNetwork(network.id));
      this.authorizing.set(null);
      this.attested.set(false);
      await this.reloadNetworks();
    });
  }

  async revokeAuthorization(network: Network): Promise<void> {
    await this.run(async () => {
      await firstValueFrom(this.api.revokeNetworkAuthorization(network.id));
      await this.reloadNetworks();
    });
  }

  async deleteNetwork(network: Network): Promise<void> {
    await this.run(async () => {
      await firstValueFrom(this.api.deleteNetwork(network.id));
      this.confirmingNetworkDelete.set(null);
      await this.reloadNetworks();
    });
  }

  private async reloadNetworks(): Promise<void> {
    this.networks.set(await firstValueFrom(this.api.networks(this.id())));
  }

  async createToken(): Promise<void> {
    await this.run(async () => {
      this.created.set(await firstValueFrom(this.api.createEnrollmentToken(this.id())));
      this.tokens.set(await firstValueFrom(this.api.enrollmentTokens(this.id())));
    });
  }

  async revokeToken(token: EnrollmentToken): Promise<void> {
    await this.run(async () => {
      await firstValueFrom(this.api.revokeEnrollmentToken(token.id));
      if (this.created()?.id === token.id) {
        this.created.set(null);
      }
      this.tokens.set(await firstValueFrom(this.api.enrollmentTokens(this.id())));
    });
  }

  async revokeAgent(agent: Agent): Promise<void> {
    await this.run(async () => {
      await firstValueFrom(this.api.revokeAgent(agent.id, 'revoked from dashboard'));
      this.confirmingRevoke.set(null);
      this.agents.set(await firstValueFrom(this.api.agents(this.id())));
    });
  }

  /** Shows or hides the self-diagnosis of an agent; its recent events are loaded on opening. */
  async toggleDiagnosis(agent: Agent): Promise<void> {
    if (this.expanded() === agent.id) {
      this.expanded.set(null);
      return;
    }
    this.expanded.set(agent.id);
    this.events.set([]);
    await this.run(async () => {
      this.events.set(await firstValueFrom(this.api.agentEvents(agent.id)));
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

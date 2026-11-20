import { ChangeDetectionStrategy, Component, OnDestroy, OnInit, computed, inject, input, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { TranslocoPipe } from '@jsverse/transloco';
import { firstValueFrom } from 'rxjs';
import { ApiProblem, toApiProblem } from '../../core/api/api-error';
import { AuthService } from '../../core/auth/auth.service';
import { CONFIRMABLE_FIELDS, DEVICE_CATEGORIES, Device, DeviceServices, DevicesApi } from '../../core/devices/devices.api';
import { DeviceImage, DeviceImagesApi, IMAGE_UPLOAD_MAX_BYTES, IMAGE_UPLOAD_TYPES, revokeAll } from '../../core/devices/device-images.api';
import { LocalizedDatePipe } from '../../core/i18n/localized-date.pipe';
import { PeopleApi, Person, PersonDevice } from '../../core/people/people.api';
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
  styles: [`
    .thumb { width: 32px; height: 32px; object-fit: cover; border-radius: 6px; vertical-align: middle; margin-right: 6px; }
    .photo { max-width: 200px; max-height: 200px; border-radius: 8px; border: 1px solid var(--border); display: block; }
  `],
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
              @if (canReadPeople()) { <th>{{ 'people.person' | transloco }}</th> }
              <th>{{ 'devices.lastSeen' | transloco }}</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            @for (d of devices(); track d.id) {
              <tr>
                <td>@if (images().get(d.id); as src) { <img class="thumb" [src]="src" alt="" [attr.data-testid]="'thumb-' + d.id" /> }{{ d.displayName ?? d.hostname ?? '—' }}</td>
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
                @if (canReadPeople()) {
                  <td [attr.data-testid]="'people-' + d.id">
                    @for (p of peopleOf(d.id); track p.person.id) {
                      <div>{{ p.person.name }}@if (p.link.status === 'PROBABLE') { <span class="badge warn">{{ 'people.probable' | transloco }}</span> }</div>
                    } @empty { — }
                  </td>
                }
                <td>
                  {{ d.lastSeenAt | appDate: 'short' }}
                  @if (latestScanId() && d.lastScanId !== latestScanId()) {
                    <span class="badge" [attr.data-testid]="'stale-' + d.id">{{ 'devices.notInLastScan' | transloco }}</span>
                  }
                </td>
                <td><button type="button" (click)="open(d)" [disabled]="busy()">{{ 'devices.show' | transloco }}</button></td>
              </tr>
            }
          </tbody>
        </table>
      }
      @if (canReadPeople() && people().length) {
        <h2>{{ 'people.homeTitle' | transloco }}</h2>
        <ul data-testid="home-people">
          @for (p of people(); track p.id) {
            <li>{{ p.name }} <span class="muted small">· {{ 'people.deviceCount' | transloco: { count: p.devices.length } }}
              · {{ 'people.source.' + p.origin | transloco }}</span>
              @if (canManagePeople()) {
                <button type="button" [attr.data-testid]="'person-delete-' + p.id" (click)="deletePerson(p)" [disabled]="busy()">
                  {{ 'people.delete' | transloco }}</button>
              }
            </li>
          }
        </ul>
        <p class="muted small">{{ 'people.privacyNote' | transloco }}</p>
      }
    </section>

    @if (selected(); as d) {
      <section class="card wide" data-testid="device-detail">
        <h2>{{ d.displayName ?? d.hostname ?? d.ip ?? d.mac }}</h2>
        <div data-testid="device-photo">
          @if (images().get(d.id); as src) {
            <img class="photo" [src]="src" [alt]="d.displayName ?? d.hostname ?? d.ip ?? ''" />
          }
          @if (shownImage(); as img) {
            <p class="muted small" data-testid="photo-source">{{ 'devices.photo.source.' + img.source | transloco }}</p>
          } @else {
            <p class="muted small" data-testid="no-photo">{{ 'devices.photo.none' | transloco }}</p>
          }
          @if (canClassify()) {
            <label>{{ 'devices.photo.upload' | transloco }}
              <input type="file" data-testid="photo-input" accept="image/png,image/jpeg" [disabled]="busy()"
                     (change)="uploadPhoto(d, $any($event.target))" />
            </label>
            @if (hasUserPhoto()) {
              <button type="button" data-testid="photo-remove" (click)="removePhoto(d)" [disabled]="busy()">
                {{ 'devices.photo.remove' | transloco }}</button>
            }
            <p class="muted small">{{ 'devices.photo.hint' | transloco }}</p>
          }
        </div>
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
          <p class="muted" data-testid="randomized-note">{{ 'devices.randomizedNote' | transloco }}</p>
        }
        @if (sameAs(d); as other) {
          <div class="alert warning" role="status" data-testid="same-as">
            {{ 'devices.probableSameAs' | transloco: { name: other } }}
            @if (canClassify()) {
              @if (confirmMerge()) {
                <p>{{ 'devices.mergeWarning' | transloco: { name: other } }}</p>
                <button type="button" data-testid="merge-confirm" (click)="merge(d)" [disabled]="busy()">
                  {{ 'devices.mergeConfirm' | transloco }}</button>
                <button type="button" (click)="confirmMerge.set(false)" [disabled]="busy()">
                  {{ 'devices.cancel' | transloco }}</button>
              } @else {
                <button type="button" data-testid="merge" (click)="confirmMerge.set(true)" [disabled]="busy()">
                  {{ 'devices.merge' | transloco }}</button>
                <button type="button" data-testid="dismiss-same-as" (click)="dismissSameAs(d)" [disabled]="busy()">
                  {{ 'devices.notSame' | transloco }}</button>
              }
            }
          </div>
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

        @if (canReadPeople()) {
          <h3>{{ 'people.title' | transloco }}</h3>
          <table class="list" data-testid="device-people">
            <tbody>
              @for (p of peopleOf(d.id); track p.person.id) {
                <tr>
                  <td><strong>{{ p.person.name }}</strong></td>
                  <td>
                    <span class="badge" [class.ok]="p.link.status === 'CONFIRMED'" [class.warn]="p.link.status === 'PROBABLE'">
                      {{ 'people.status.' + p.link.status | transloco }}</span>
                  </td>
                  <td class="small muted">{{ 'people.source.' + p.link.source | transloco }}@if (p.link.evidence) { : {{ p.link.evidence }} }</td>
                  <td>
                    @if (canManagePeople()) {
                      @if (p.link.status === 'PROBABLE') {
                        <button type="button" [attr.data-testid]="'person-confirm-' + p.person.id" (click)="assign(d, p.person.id)" [disabled]="busy()">
                          {{ 'people.confirm' | transloco }}</button>
                      }
                      <button type="button" [attr.data-testid]="'person-remove-' + p.person.id" (click)="unassign(d, p.person.id)" [disabled]="busy()">
                        {{ 'people.remove' | transloco }}</button>
                    }
                  </td>
                </tr>
              } @empty {
                <tr><td colspan="4" class="muted">{{ 'people.none' | transloco }}</td></tr>
              }
            </tbody>
          </table>
          @if (canManagePeople()) {
            <label>{{ 'people.assign' | transloco }}
              <select #who data-testid="person-select" [disabled]="busy()">
                @for (p of people(); track p.id) { <option [value]="p.id">{{ p.name }}</option> }
              </select>
            </label>
            <button type="button" data-testid="person-assign" (click)="who.value && assign(d, who.value)"
                    [disabled]="busy() || people().length === 0">{{ 'people.assignButton' | transloco }}</button>
            <label>{{ 'people.newPerson' | transloco }}
              <input #newName data-testid="person-new" maxlength="100" [disabled]="busy()" />
            </label>
            <button type="button" data-testid="person-create" (click)="createAndAssign(d, newName)" [disabled]="busy()">
              {{ 'people.createButton' | transloco }}</button>
          }
          <p class="muted small">{{ 'people.privacyNote' | transloco }}</p>
        }

        <h3>{{ 'devices.card.title' | transloco }}</h3>
        @if (canClassify()) {
          <label>
            {{ 'devices.card.customName' | transloco }}
            <input #nameInput data-testid="custom-name" maxlength="100" [value]="d.customName ?? ''" [disabled]="busy()" />
          </label>
          <button type="button" data-testid="custom-name-save" (click)="rename(d, nameInput.value)" [disabled]="busy()">
            {{ 'devices.card.save' | transloco }}</button>
          @if (d.customName) {
            <button type="button" (click)="rename(d, '')" [disabled]="busy()">{{ 'devices.card.clear' | transloco }}</button>
          }
          <p class="muted small">{{ 'devices.card.customNameHint' | transloco }}</p>
        }
        <table class="list" data-testid="identity">
          <tbody>
            @for (f of d.identity ?? []; track f.field) {
              <tr>
                <td>{{ 'devices.fields.' + f.field | transloco }}</td>
                <td><strong>{{ f.value ?? '—' }}</strong></td>
                <td>
                  <span class="badge" [class.ok]="f.status === 'VERIFIED'" [class.warn]="f.status === 'PROBABLE'"
                        [attr.data-status]="f.status">{{ 'devices.status.' + f.status | transloco }}</span>
                  @if (f.userConfirmed) { <span class="badge ok">{{ 'devices.card.userConfirmed' | transloco }}</span> }
                  @if (f.conflict) { <span class="badge err">{{ 'devices.conflict' | transloco }}</span> }
                </td>
                <td class="small muted">{{ f.sources.join(', ') }}</td>
                <td>
                  @if (canClassify() && confirmable(f.field)) {
                    @if (f.userConfirmed) {
                      <button type="button" (click)="confirmField(d, f.field, null)" [disabled]="busy()">
                        {{ 'devices.card.unconfirm' | transloco }}</button>
                    } @else {
                      @if (f.value) {
                        <button type="button" [attr.data-testid]="'confirm-' + f.field"
                                (click)="confirmField(d, f.field, f.value)" [disabled]="busy()">
                          {{ 'devices.card.confirm' | transloco }}</button>
                      }
                      <input #fix [attr.aria-label]="'devices.card.correct' | transloco" maxlength="255" size="12" />
                      <button type="button" (click)="fix.value.trim() && confirmField(d, f.field, fix.value)"
                              [disabled]="busy()">{{ 'devices.card.correct' | transloco }}</button>
                    }
                  }
                </td>
              </tr>
            }
          </tbody>
        </table>
        <p class="muted small">{{ 'devices.card.statusRule' | transloco }}</p>

        <h3>{{ 'devices.card.history' | transloco }}</h3>
        <table class="list" data-testid="identification-history">
          <tbody>
            @for (c of d.identificationHistory ?? []; track $index) {
              <tr>
                <td>{{ c.changedAt | appDate: 'short' }}</td>
                <td>{{ 'devices.fields.' + c.field | transloco }}</td>
                <td>{{ c.oldValue ?? '—' }} → <strong>{{ c.newValue ?? '—' }}</strong></td>
                <td>@if (c.newStatus) { {{ 'devices.status.' + c.newStatus | transloco }} }</td>
                <td class="muted">{{ 'devices.card.origin.' + c.origin | transloco }}</td>
              </tr>
            } @empty {
              <tr><td colspan="5" class="muted">{{ 'devices.card.noHistory' | transloco }}</td></tr>
            }
          </tbody>
        </table>

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

        <h3>{{ 'devices.interfaces.title' | transloco }}</h3>
        <table class="list" data-testid="interfaces">
          <thead>
            <tr>
              <th>{{ 'devices.mac' | transloco }}</th>
              <th>{{ 'devices.interfaces.vendor' | transloco }}</th>
              <th>{{ 'devices.interfaces.seenVia' | transloco }}</th>
              <th>{{ 'devices.addressesTable.firstSeen' | transloco }}</th>
              <th>{{ 'devices.lastSeen' | transloco }}</th>
            </tr>
          </thead>
          <tbody>
            @for (i of d.interfaces ?? []; track i.mac) {
              <tr [class.muted]="!i.current">
                <td><code>{{ i.mac }}</code>
                  @if (i.macRandomized) { <span class="badge warn">{{ 'devices.randomized' | transloco }}</span> }
                  @if (!i.current) { <span class="badge">{{ 'devices.addressesTable.past' | transloco }}</span> }
                </td>
                <td>{{ i.vendor ?? '—' }}</td>
                <td>{{ i.agentInterface ?? '—' }}</td>
                <td>{{ i.firstSeenAt | appDate: 'short' }}</td>
                <td>{{ i.lastSeenAt | appDate: 'short' }}</td>
              </tr>
            } @empty {
              <tr><td colspan="5" class="muted">{{ 'devices.interfaces.none' | transloco }}</td></tr>
            }
          </tbody>
        </table>

        <h3>{{ 'devices.addressesTable.title' | transloco }}</h3>
        <table class="list" data-testid="addresses">
          <thead>
            <tr>
              <th>{{ 'devices.addressesTable.address' | transloco }}</th>
              <th>{{ 'devices.addressesTable.type' | transloco }}</th>
              <th>{{ 'devices.mac' | transloco }}</th>
              <th>{{ 'devices.addressesTable.firstSeen' | transloco }}</th>
              <th>{{ 'devices.lastSeen' | transloco }}</th>
              <th>{{ 'devices.addressesTable.timesSeen' | transloco }}</th>
            </tr>
          </thead>
          <tbody>
            @for (a of d.addressHistory ?? []; track a.address) {
              <tr [class.muted]="!a.current">
                <td><code>{{ a.address }}</code>
                  @if (a.current) { <span class="badge ok">{{ 'devices.addressesTable.current' | transloco }}</span> }
                  @else { <span class="badge">{{ 'devices.addressesTable.past' | transloco }}</span> }
                </td>
                <td>IPv{{ a.family }}
                  @if (a.scope) { · {{ 'devices.scope.' + a.scope | transloco }} }
                  @if (a.interfaceId) { · {{ 'devices.interfaceId.' + a.interfaceId | transloco }} }
                </td>
                <td><code>{{ a.mac ?? '—' }}</code></td>
                <td>{{ a.firstSeenAt | appDate: 'short' }}</td>
                <td>{{ a.lastSeenAt | appDate: 'short' }}</td>
                <td>{{ a.timesSeen }}</td>
              </tr>
            }
          </tbody>
        </table>
        <p class="muted small">{{ 'devices.addressesTable.note' | transloco }}</p>

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
export class DevicesPage implements OnInit, OnDestroy {
  private readonly api = inject(DevicesApi);
  private readonly auth = inject(AuthService);
  private readonly imagesApi = inject(DeviceImagesApi);
  private readonly peopleApi = inject(PeopleApi);

  /** Route parameter :id (component input binding). */
  readonly homeId = input.required<string>({ alias: 'id' });

  readonly categories = DEVICE_CATEGORIES.filter((c) => c !== 'UNKNOWN_DEVICE');
  readonly devices = signal<Device[]>([]);
  /** Scan of the most recently seen device: the last scan that found anything in the home. */
  readonly latestScanId = computed(() => {
    let latest: Device | null = null;
    for (const d of this.devices()) {
      if (d.lastScanId && (!latest || d.lastSeenAt > latest.lastSeenAt)) {
        latest = d;
      }
    }
    return latest?.lastScanId ?? null;
  });
  readonly selected = signal<Device | null>(null);
  readonly busy = signal(false);
  readonly problem = signal<ApiProblem | null>(null);
  /** Image shown for each device (object URL), images of the selected device (USER first). */
  readonly images = signal<Map<string, string>>(new Map());
  readonly selectedImages = signal<DeviceImage[]>([]);

  shownImage(): DeviceImage | null {
    return this.selectedImages()[0] ?? null;
  }

  hasUserPhoto(): boolean {
    return this.selectedImages().some((i) => i.source === 'USER');
  }

  /** People of the home (M24); empty without person:read. */
  readonly people = signal<Person[]>([]);

  canReadPeople(): boolean {
    return this.auth.hasPermission('person:read');
  }

  canManagePeople(): boolean {
    return this.auth.hasPermission('person:manage');
  }

  /** People associated with a device: confirmed first, then probable. */
  peopleOf(deviceId: string): { person: Person; link: PersonDevice }[] {
    const out: { person: Person; link: PersonDevice }[] = [];
    for (const person of this.people()) {
      const link = person.devices.find((x) => x.deviceId === deviceId);
      if (link) {
        out.push({ person, link });
      }
    }
    return out.sort((a, b) => (a.link.status === b.link.status ? a.person.name.localeCompare(b.person.name)
      : a.link.status === 'CONFIRMED' ? -1 : 1));
  }

  async assign(d: Device, personId: string): Promise<void> {
    await this.run(async () => this.replacePerson(await firstValueFrom(this.peopleApi.assign(d.id, personId))));
  }

  async unassign(d: Device, personId: string): Promise<void> {
    await this.run(async () => this.replacePerson(await firstValueFrom(this.peopleApi.unassign(d.id, personId))));
  }

  async createAndAssign(d: Device, input: HTMLInputElement): Promise<void> {
    const name = input.value.trim();
    if (!name) {
      return;
    }
    await this.run(async () => {
      const created = await firstValueFrom(this.peopleApi.create(this.homeId(), name));
      this.replacePerson(await firstValueFrom(this.peopleApi.assign(d.id, created.id)));
      input.value = '';
    });
  }

  async deletePerson(p: Person): Promise<void> {
    await this.run(async () => {
      await firstValueFrom(this.peopleApi.remove(p.id));
      this.people.update((list) => list.filter((x) => x.id !== p.id));
    });
  }

  private replacePerson(updated: Person): void {
    this.people.update((list) => {
      const others = list.filter((p) => p.id !== updated.id);
      return [...others, updated].sort((a, b) => a.name.localeCompare(b.name));
    });
  }

  private async loadPeople(): Promise<void> {
    if (!this.canReadPeople()) {
      return;
    }
    try {
      this.people.set(await firstValueFrom(this.peopleApi.list(this.homeId())));
    } catch (error) {
      this.problem.set(toApiProblem(error));
    }
  }

  canClassify(): boolean {
    return this.auth.hasPermission('device:classify');
  }

  label(category: string | null): string {
    return category ? `devices.categories.${category}` : 'devices.automatic';
  }

  /** Two-step confirmation of a merge ("same device"). */
  readonly confirmMerge = signal(false);

  /** Name of the device that this one (privacy MAC, second interface) probably is, if known. */
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
    void this.loadImages();
    void this.loadPeople();
  }

  ngOnDestroy(): void {
    revokeAll(this.images().values());
  }

  /** Images are an extra: if they cannot be loaded the inventory is shown without them. */
  private async loadImages(): Promise<void> {
    try {
      const loaded = await this.imagesApi.loadShown(this.homeId());
      revokeAll(this.images().values());
      this.images.set(loaded);
    } catch {
      // no images
    }
  }

  async uploadPhoto(d: Device, input: HTMLInputElement): Promise<void> {
    const file = input.files?.[0];
    input.value = '';
    if (!file) {
      return;
    }
    if (!IMAGE_UPLOAD_TYPES.includes(file.type) || file.size > IMAGE_UPLOAD_MAX_BYTES) {
      this.problem.set({ status: 400, code: 'INVALID_IMAGE', messageKey: 'devices.photo.invalid', violations: [] });
      return;
    }
    await this.run(async () => {
      this.selectedImages.set(await firstValueFrom(this.imagesApi.upload(d.id, file)));
      await this.loadImages();
    });
  }

  async removePhoto(d: Device): Promise<void> {
    await this.run(async () => {
      this.selectedImages.set(await firstValueFrom(this.imagesApi.remove(d.id)));
      await this.loadImages();
    });
  }

  async open(d: Device): Promise<void> {
    this.confirmMerge.set(false);
    this.selectedImages.set([]);
    await this.run(async () => this.selected.set(await firstValueFrom(this.api.get(d.id))));
    try {
      this.selectedImages.set(await firstValueFrom(this.imagesApi.ofDevice(d.id)));
    } catch {
      // no image metadata: no caption
    }
  }

  /** The user confirmed: d is merged into the device it probably is, which becomes the selected one. */
  async merge(d: Device): Promise<void> {
    const into = d.probableSameAs;
    if (!into) {
      return;
    }
    await this.run(async () => {
      const merged = await firstValueFrom(this.api.merge(d.id, into));
      this.confirmMerge.set(false);
      this.selected.set(merged);
      this.devices.update((list) => list.filter((x) => x.id !== d.id).map((x) => (x.id === merged.id ? merged : x)));
    });
  }

  async dismissSameAs(d: Device): Promise<void> {
    const other = d.probableSameAs;
    if (!other) {
      return;
    }
    await this.run(async () => {
      const updated = await firstValueFrom(this.api.dismissSameAs(d.id, other));
      this.selected.set(updated);
      this.devices.update((list) => list.map((x) => (x.id === updated.id ? updated : x)));
    });
  }

  confirmable(field: string): boolean {
    return CONFIRMABLE_FIELDS.includes(field);
  }

  async confirmField(d: Device, field: string, value: string | null): Promise<void> {
    await this.run(async () => this.replace(await firstValueFrom(this.api.confirmField(d.id, field, value))));
  }

  async rename(d: Device, name: string): Promise<void> {
    const value = name.trim() || null;
    await this.run(async () => this.replace(await firstValueFrom(this.api.rename(d.id, value))));
  }

  private replace(updated: Device): void {
    this.selected.set(updated);
    this.devices.update((list) => list.map((x) => (x.id === updated.id ? { ...x, ...updated, identity: undefined } : x)));
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

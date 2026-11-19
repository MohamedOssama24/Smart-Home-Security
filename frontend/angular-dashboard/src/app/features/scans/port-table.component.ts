import { ChangeDetectionStrategy, Component, input } from '@angular/core';
import { TranslocoPipe } from '@jsverse/transloco';
import { OpenPort } from '../../core/scans/scans.api';

/**
 * Open ports and their services (Milestone 9). A PROBABLE service is only a guess from the
 * port number; a CONFIRMED one answered its protocol. Product, version and titles are what
 * the device declared: shown as such, never as verified facts.
 */
@Component({
  selector: 'app-port-table',
  imports: [TranslocoPipe],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    @if (ports().length === 0) {
      <p class="muted" data-testid="no-ports">{{ 'ports.none' | transloco }}</p>
    } @else {
      <table class="list" data-testid="ports">
        <thead>
          <tr>
            @if (showIp()) {
              <th>{{ 'ports.ip' | transloco }}</th>
            }
            <th>{{ 'ports.port' | transloco }}</th>
            <th>{{ 'ports.service' | transloco }}</th>
            <th>{{ 'ports.product' | transloco }}</th>
            <th>{{ 'ports.details' | transloco }}</th>
          </tr>
        </thead>
        <tbody>
          @for (p of ports(); track p.ip + p.protocol + p.port) {
            <tr>
              @if (showIp()) {
                <td><code>{{ p.ip }}</code></td>
              }
              <td><code>{{ p.port }}/{{ p.protocol.toLowerCase() }}</code></td>
              <td>
                @if (p.service; as s) {
                  <strong>{{ s.name }}</strong>
                  <span class="badge" [class.ok]="s.status === 'CONFIRMED'" [class.warn]="s.status === 'PROBABLE'">
                    {{ 'ports.status.' + s.status | transloco }}</span>
                } @else {
                  —
                }
              </td>
              <td>{{ p.service?.product ?? '—' }} {{ p.service?.version ?? '' }}</td>
              <td class="small" data-testid="port-details">
                @for (d of details(p); track d.key) {
                  <div>{{ 'ports.evidence.' + d.key | transloco: { value: d.value } }}</div>
                }
              </td>
            </tr>
          }
        </tbody>
      </table>
      <p class="muted small">{{ 'ports.declaredNote' | transloco }}</p>
    }
  `,
})
export class PortTableComponent {
  readonly ports = input.required<OpenPort[]>();
  readonly showIp = input(false);

  /** The evidence worth showing, as translation keys with their value. */
  details(p: OpenPort): { key: string; value: string }[] {
    const e = p.service?.evidence ?? {};
    const tls = p.service?.tls ?? null;
    const out: { key: string; value: string }[] = [];
    const text = (key: string) => {
      const v = e[key];
      if (typeof v === 'string' && v) {
        out.push({ key, value: v });
      }
    };
    text('title');
    text('server');
    text('dialect');
    if (e['authRequired'] === true) {
      out.push({ key: 'authRequired', value: '' });
    }
    if (e['loginForm'] === true) {
      out.push({ key: 'loginForm', value: '' });
    }
    if (e['redirectsToHttps'] === true) {
      out.push({ key: 'redirectsToHttps', value: '' });
    }
    if (e['smb1'] === true) {
      out.push({ key: 'smb1', value: '' });
    }
    if (e['signingRequired'] === false && p.service?.name === 'smb') {
      out.push({ key: 'signingNotRequired', value: '' });
    }
    if (tls) {
      const versions = Array.isArray(tls['versions']) ? (tls['versions'] as string[]).join(', ') : '';
      if (versions) {
        out.push({ key: 'tlsVersions', value: versions });
      }
      if (tls['expired'] === true) {
        out.push({ key: 'tlsExpired', value: '' });
      }
      if (tls['selfSigned'] === true) {
        out.push({ key: 'tlsSelfSigned', value: '' });
      }
    }
    return out;
  }
}

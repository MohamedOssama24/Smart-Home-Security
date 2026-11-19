import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { signal } from '@angular/core';
import { provideRouter } from '@angular/router';
import { AuthService } from '../../core/auth/auth.service';
import { Device } from '../../core/devices/devices.api';
import { Network } from '../../core/homes/homes.api';
import { RiskDevice, RiskOverview, RiskSnapshot } from '../../core/risk/risk.api';
import { ME } from '../../testing/auth-fixtures';
import { nextRequest, settle } from '../../testing/http';
import { translocoTesting } from '../../testing/transloco-testing';
import { inCidr, layoutNetworkMap } from './network-layout';
import { NetworkMapPage } from './network-map.page';

// [MOCK] devices on 192.168.60.0/24
const device = (id: string, ip: string | null, category: string, hostname: string | null): Device => ({
  id, homeId: 'h1', mac: null, macRandomized: false, probableSameAs: null, ip, addresses: ip ? [ip] : [], hostname,
  manufacturer: null, model: null, os: null, category, detectedCategory: category, detectedCategoryConfidence: 'HIGH',
  manualCategory: null, manualCategoryAt: null, suggestedCategory: null, overallConfidence: 'HIGH',
  rulesetVersion: '2026.11-1', classification: null, firstSeenAt: '2026-11-18T09:00:00Z',
  lastSeenAt: '2026-11-18T09:00:00Z', lastScanId: 's1', identifications: null, categoryHistory: null,
});
const ROUTER = device('d1', '192.168.60.1', 'ROUTER', 'mock-router');
const CAMERA = device('d2', '192.168.60.30', 'IP_CAMERA', 'mock-camera');
const TV = device('d3', '192.168.60.40', 'SMART_TV', 'mock-tv');
const GUEST = device('d4', '10.9.0.5', 'SMARTPHONE', 'mock-guest');
const LAN: Network = {
  id: 'n1', homeId: 'h1', name: 'LAN casa', cidr: '192.168.60.0/24', ipVersion: 4, kind: 'WIFI', source: 'MANUAL',
  authorized: true, authorization: null, createdAt: '2026-11-18T09:00:00Z', updatedAt: '2026-11-18T09:00:00Z',
};
const riskDevice = (deviceId: string, applied: number, exposed = false): RiskDevice => ({
  deviceId, name: null, ip: null, category: null, criticality: 1, exposed, raw: applied, applied, capped: false, findings: 1,
});
const SNAPSHOT = {
  id: 'r1', homeId: 'h1', scanId: 's1', scanProfile: 'STANDARD', trigger: 'SCAN', score: 70, riskLevel: 'MEDIUM',
  rating: 'FAIR', notComputedReason: null, coverage: 0.81, provisional: false, coverageDetail: {},
  breakdown: { devices: [riskDevice('d2', 29.25, true), riskDevice('d1', 3)] }, topDevices: [], delta: null,
  computedAt: '2026-11-18T09:00:00Z', engineVersion: '2026.11-1',
} as unknown as RiskSnapshot;

describe('network layout', () => {
  it('checks IPv4 and IPv6 containment', () => {
    expect(inCidr('192.168.60.30', '192.168.60.0/24')).toBe(true);
    expect(inCidr('192.168.61.30', '192.168.60.0/24')).toBe(false);
    expect(inCidr('10.9.0.5', '10.0.0.0/8')).toBe(true);
    expect(inCidr('2001:db8:0:1::5', '2001:db8:0:1::/64')).toBe(true);
    expect(inCidr('2001:db8:0:2::5', '2001:db8:0:1::/64')).toBe(false);
    expect(inCidr('192.168.60.30', '2001:db8::/64')).toBe(false);
  });

  it('puts the router at the center and the devices outside every network apart', () => {
    const many = Array.from({ length: 30 }, (_, i) => device(`m${i}`, `192.168.60.${100 + i}`, 'IOT', null));
    const groups = layoutNetworkMap([TV, CAMERA, ROUTER, GUEST, ...many], [LAN], null);
    expect(groups.map((g) => g.network?.cidr ?? null)).toEqual(['192.168.60.0/24', null]);
    const lan = groups[0];
    expect(lan.gateway!.device.id).toBe('d1');
    expect([lan.gateway!.x, lan.gateway!.y]).toEqual([lan.center.x, lan.center.y]);
    expect(lan.nodes).toHaveLength(32);
    const positions = new Set(lan.nodes.map((n) => `${n.x},${n.y}`));
    expect(positions.size).toBe(32); // no overlapping nodes
    for (const n of lan.nodes) {
      expect(n.x).toBeGreaterThan(0);
      expect(n.x).toBeLessThan(lan.width);
      expect(n.y).toBeLessThan(lan.height);
      expect(n.level).toBe('unknown'); // no score
    }
    expect(groups[1].gateway).toBeNull();
  });
});

describe('NetworkMapPage', () => {
  async function setup(overview: RiskOverview | null, permissions = ['device:read', 'home:read', 'finding:read']) {
    await TestBed.configureTestingModule({
      imports: [NetworkMapPage, translocoTesting()],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideRouter([]),
        { provide: AuthService, useValue: { hasPermission: (p: string) => permissions.includes(p), me: signal(ME) } },
      ],
    }).compileComponents();
    const http = TestBed.inject(HttpTestingController);
    const fixture = TestBed.createComponent(NetworkMapPage);
    fixture.componentRef.setInput('id', 'h1');
    fixture.detectChanges();
    (await nextRequest(http, '/api/v1/homes/h1/devices')).flush([ROUTER, CAMERA, TV]);
    (await nextRequest(http, '/api/v1/homes/h1/networks')).flush([LAN]);
    if (overview) {
      (await nextRequest(http, '/api/v1/homes/h1/risk')).flush(overview);
    }
    await settle();
    fixture.detectChanges();
    http.verify();
    return { fixture, page: fixture.nativeElement as HTMLElement };
  }

  const el = (root: HTMLElement, id: string) => root.querySelector<HTMLElement>(`[data-testid="${id}"]`);

  it('colors the devices by the points of the last score, links the exposed ones to the Internet, shows details', async () => {
    const current = { ...SNAPSHOT, id: 'r2', score: null, breakdown: {} } as RiskSnapshot; // after a Discovery scan
    const { fixture, page } = await setup({ current, lastScored: SNAPSHOT });
    const group = el(page, 'group-192.168.60.0/24')!;
    expect(group.querySelector('[data-testid="node-d2"]')!.getAttribute('class')).toContain('high');
    expect(group.querySelector('[data-testid="node-d1"]')!.getAttribute('class')).toContain('low');
    expect(group.querySelector('[data-testid="node-d3"]')!.getAttribute('class')).toContain('none');
    expect(group.querySelectorAll('path.exposure')).toHaveLength(1);
    expect(el(page, 'legend')!.textContent).toContain('Punteggio 70');

    group.querySelector<SVGGElement>('[data-testid="node-d2"]')!.dispatchEvent(new MouseEvent('click'));
    fixture.detectChanges();
    expect(el(page, 'details')!.textContent).toContain('mock-camera');
    expect(el(page, 'points')!.textContent).toContain('−29.25');
    expect(el(page, 'details')!.textContent).toContain('Esposto a Internet');
    expect(el(page, 'device-table')!.textContent).toContain('192.168.60.40');
  });

  it('without finding:read shows the devices only', async () => {
    const { page } = await setup(null, ['device:read', 'home:read']);
    expect(el(page, 'no-risk')).not.toBeNull();
    expect(page.querySelector('[data-testid="node-d2"]')!.getAttribute('class')).toContain('unknown');
  });
});

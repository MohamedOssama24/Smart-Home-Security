import { Device } from '../../core/devices/devices.api';
import { Network } from '../../core/homes/homes.api';
import { RiskDevice } from '../../core/risk/risk.api';

/** Risk class of a node: points the device takes off the last computed score. */
export type NodeRisk = 'none' | 'low' | 'high' | 'unknown';

export interface MapNode {
  device: Device;
  risk: RiskDevice | null;
  level: NodeRisk;
  exposed: boolean;
  x: number;
  y: number;
}

export interface MapGroup {
  /** null: devices outside every configured network (or without an address). */
  network: Network | null;
  /** Router of the group at the center; null when no device was classified as a router. */
  gateway: MapNode | null;
  nodes: MapNode[];
  width: number;
  height: number;
  center: { x: number; y: number };
  internet: { x: number; y: number };
}

/** Points threshold above which a device is drawn as high risk (one HIGH finding ≈ 15). */
export const HIGH_RISK_POINTS = 15;
const RING_STEP = 90;
const FIRST_RING = 110;
const MARGIN = 70;
const INTERNET_GAP = 70;

/**
 * Logical map of the home: one star per authorized network, the router (when identified) at
 * the center and the other devices on rings around it. The links say which network a device
 * is on, not how it is cabled (that is not observable from the LAN).
 */
export function layoutNetworkMap(devices: Device[], networks: Network[], risk: RiskDevice[] | null): MapGroup[] {
  const byDevice = new Map((risk ?? []).map((r) => [r.deviceId, r]));
  const groups = new Map<string, { network: Network | null; devices: Device[] }>();
  for (const n of networks) {
    groups.set(n.id, { network: n, devices: [] });
  }
  const other: Device[] = [];
  for (const d of [...devices].sort(compareIp)) {
    const net = networks.find((n) => d.ip !== null && inCidr(d.ip, n.cidr));
    if (net) {
      groups.get(net.id)!.devices.push(d);
    } else {
      other.push(d);
    }
  }
  const out: MapGroup[] = [];
  for (const g of groups.values()) {
    if (g.devices.length) {
      out.push(layoutGroup(g.network, g.devices, byDevice, risk !== null));
    }
  }
  if (other.length) {
    out.push(layoutGroup(null, other, byDevice, risk !== null));
  }
  return out;
}

function layoutGroup(network: Network | null, devices: Device[], risk: Map<string, RiskDevice>,
  hasRisk: boolean): MapGroup {
  const node = (d: Device): MapNode => {
    const r = risk.get(d.id) ?? null;
    return { device: d, risk: r, level: level(r, hasRisk), exposed: r?.exposed ?? false, x: 0, y: 0 };
  };
  const routerIndex = devices.findIndex((d) => d.category === 'ROUTER');
  const gateway = routerIndex >= 0 ? node(devices[routerIndex]) : null;
  const rest = devices.filter((_, i) => i !== routerIndex).map(node);

  // rings: capacity grows with the circumference
  const rings: MapNode[][] = [];
  let index = 0;
  for (let ring = 0; index < rest.length; ring++) {
    const capacity = Math.max(6, Math.floor((2 * Math.PI * (FIRST_RING + ring * RING_STEP)) / 95));
    rings.push(rest.slice(index, index + capacity));
    index += capacity;
  }
  const outer = rings.length ? FIRST_RING + (rings.length - 1) * RING_STEP : FIRST_RING;
  const size = 2 * (outer + MARGIN);
  const center = { x: size / 2, y: size / 2 + INTERNET_GAP };
  rings.forEach((members, ring) => {
    const radius = FIRST_RING + ring * RING_STEP;
    const offset = ring % 2 ? Math.PI / members.length : 0;
    members.forEach((m, i) => {
      // start at the bottom: the top is left free for the link to the Internet
      const angle = Math.PI / 2 + offset + (2 * Math.PI * i) / members.length;
      m.x = round(center.x + radius * Math.cos(angle));
      m.y = round(center.y + radius * Math.sin(angle));
    });
  });
  if (gateway) {
    gateway.x = center.x;
    gateway.y = center.y;
  }
  return {
    network,
    gateway,
    nodes: rest,
    width: size,
    height: size + INTERNET_GAP,
    center,
    internet: { x: center.x, y: 30 },
  };
}

function level(r: RiskDevice | null, hasRisk: boolean): NodeRisk {
  if (!hasRisk) {
    return 'unknown';
  }
  if (!r || r.applied <= 0) {
    return 'none';
  }
  return r.applied >= HIGH_RISK_POINTS ? 'high' : 'low';
}

function round(v: number): number {
  return Math.round(v * 10) / 10;
}

function compareIp(a: Device, b: Device): number {
  return ipv4Number(a.ip) - ipv4Number(b.ip) || (a.ip ?? '').localeCompare(b.ip ?? '');
}

function ipv4Number(ip: string | null): number {
  const parts = ip?.split('.').map(Number);
  if (!parts || parts.length !== 4 || parts.some((p) => !Number.isInteger(p) || p < 0 || p > 255)) {
    return Number.MAX_SAFE_INTEGER;
  }
  return ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
}

/** IPv4 containment; IPv6 networks match on the textual /64 prefix only when the prefix is ≥ 64. */
export function inCidr(ip: string, cidr: string): boolean {
  const [base, bitsText] = cidr.split('/');
  const bits = Number(bitsText);
  if (ip.includes(':') || base.includes(':')) {
    return ip.includes(':') && base.includes(':') && bits >= 64 && sameV6Prefix(ip, base);
  }
  const a = ipv4Number(ip);
  const b = ipv4Number(base);
  if (a === Number.MAX_SAFE_INTEGER || b === Number.MAX_SAFE_INTEGER || !(bits >= 0 && bits <= 32)) {
    return false;
  }
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return ((a & mask) >>> 0) === ((b & mask) >>> 0);
}

function sameV6Prefix(ip: string, base: string): boolean {
  const head = (v: string) => expandV6(v).slice(0, 4).join(':');
  return head(ip) === head(base);
}

function expandV6(v: string): string[] {
  const [left, right = ''] = v.split('::');
  const l = left ? left.split(':') : [];
  const r = right ? right.split(':') : [];
  const fill = v.includes('::') ? Array(8 - l.length - r.length).fill('0') : [];
  return [...l, ...fill, ...r].map((p) => p.toLowerCase().replace(/^0+(?=.)/, ''));
}

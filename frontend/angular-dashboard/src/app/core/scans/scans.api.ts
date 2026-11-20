import { HttpClient } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';

export type ScanStatus =
  | 'PENDING'
  | 'QUEUED'
  | 'RUNNING'
  | 'COMPLETED'
  | 'COMPLETED_WITH_WARNINGS'
  | 'FAILED'
  | 'CANCELLED';

export const ACTIVE_SCAN_STATUSES: readonly ScanStatus[] = ['PENDING', 'QUEUED', 'RUNNING'];

/** Profiles available in this version: DISCOVERY finds the hosts, QUICK and STANDARD also scan their ports. */
export const SCAN_PROFILES = ['DISCOVERY', 'QUICK', 'STANDARD'] as const;
export type ScanProfile = (typeof SCAN_PROFILES)[number];

export interface ScanEvent {
  fromStatus: ScanStatus | null;
  toStatus: ScanStatus;
  actorType: 'USER' | 'AGENT' | 'SYSTEM';
  actorId: string | null;
  reason: string | null;
  at: string;
}

export interface Scan {
  id: string;
  homeId: string;
  agentId: string;
  trigger: 'MANUAL';
  profile: string;
  status: ScanStatus;
  requestedBy: string;
  requestedAt: string;
  queuedAt: string | null;
  startedAt: string | null;
  completedAt: string | null;
  cancelRequestedAt: string | null;
  progress: { phase: string | null; percent: number | null } | null;
  devicesDiscovered: number;
  outOfScopeDropped: number;
  warnings: string[];
  failureReason: string | null;
  targets: { networkId: string; cidr: string }[] | null;
  events: ScanEvent[] | null;
}

/** A host seen by the scan (address in use on an authorized network): not a vulnerability. */
/**
 * A host seen by a scan: addresses grouped by MAC address when known (a hint, not an
 * inventory). Details declared by the device itself carry selfDeclared: true.
 */
export interface ScanDevice {
  ip: string;
  mac: string | null;
  methods: string[];
  iface: string | null;
  observedAt: string;
  addresses?: string[];
  hostname?: string | null;
  hostnames?: { name: string; method: string }[];
  evidence?: ScanEvidence[];
}

export interface ScanEvidence {
  method: string;
  ip: string;
  details: Record<string, unknown> | null;
  observedAt: string;
}

/**
 * Service identified on an open port. PROBABLE: guessed from the port number or weak evidence;
 * CONFIRMED: the device answered the protocol. Product and version are declared by the device.
 */
export interface DetectedService {
  name: string;
  product: string | null;
  version: string | null;
  status: 'PROBABLE' | 'CONFIRMED';
  confidence: 'LOW' | 'MEDIUM' | 'HIGH';
  evidence: Record<string, unknown>;
  tls: Record<string, unknown> | null;
}

/** An open port found by a QUICK or STANDARD scan. */
export type GatewayProtocol = 'ZIGBEE' | 'ZWAVE' | 'MATTER' | 'THREAD' | 'BLUETOOTH' | 'IP' | 'OTHER';

/** A device known to Home Assistant; matchedIp: host of the same scan with one of its MAC addresses. */
export interface GatewayDevice {
  name: string | null;
  manufacturer: string | null;
  model: string | null;
  swVersion: string | null;
  protocol: GatewayProtocol;
  macs: string[];
  entities: number;
  matchedIp: string | null;
}

export interface HomeAssistantInventory {
  ip: string;
  version: string | null;
  https: boolean;
  deviceCount: number;
  truncated: boolean;
  observedAt: string;
  protocols: Partial<Record<GatewayProtocol, number>>;
  devices: GatewayDevice[];
}

export interface ScanIntegrations {
  homeAssistant: HomeAssistantInventory | null;
}

export interface OpenPort {
  deviceId: string | null;
  ip: string;
  protocol: 'TCP' | 'UDP';
  port: number;
  state: string;
  reason: string | null;
  observedAt: string;
  service: DetectedService | null;
}

/** Port mapping declared by an Internet gateway over UPnP IGD. */
export interface PortMapping {
  protocol: string;
  externalPort?: number;
  internalClient: string;
  internalPort?: number;
  enabled: boolean;
  description?: string;
}

/** What a deletion removed. */
export interface DeletedCounts {
  scans: number;
  devices: number;
  findings: number;
}

@Injectable({ providedIn: 'root' })
export class ScansApi {
  private readonly http = inject(HttpClient);

  /** Manual scans only: the key makes a repeated click (or retry) return the same scan. */
  request(homeId: string, idempotencyKey: string, profile: ScanProfile = 'DISCOVERY'): Observable<Scan> {
    return this.http.post<Scan>(
      `/api/v1/homes/${encodeURIComponent(homeId)}/scans`,
      { profile },
      { headers: { 'Idempotency-Key': idempotencyKey } },
    );
  }

  history(homeId: string): Observable<Scan[]> {
    return this.http.get<Scan[]>(`/api/v1/homes/${encodeURIComponent(homeId)}/scans`);
  }

  get(scanId: string): Observable<Scan> {
    return this.http.get<Scan>(`/api/v1/scans/${encodeURIComponent(scanId)}`);
  }

  /** Irreversible: deletes a finished scan; devices and findings seen only by it are deleted too. */
  remove(scanId: string): Observable<DeletedCounts> {
    return this.http.delete<DeletedCounts>(`/api/v1/scans/${encodeURIComponent(scanId)}`);
  }

  /** Irreversible: deletes all scans, devices, findings, people, reports and alerts of the home. */
  clearHome(homeId: string): Observable<DeletedCounts> {
    return this.http.delete<DeletedCounts>(`/api/v1/homes/${encodeURIComponent(homeId)}/inventory`);
  }

  cancel(scanId: string): Observable<Scan> {
    return this.http.post<Scan>(`/api/v1/scans/${encodeURIComponent(scanId)}/cancel`, {});
  }

  devices(scanId: string): Observable<ScanDevice[]> {
    return this.http.get<ScanDevice[]>(`/api/v1/scans/${encodeURIComponent(scanId)}/devices`);
  }

  /** Integrations seen by the scan: the Home Assistant inventory, when configured on the agent (M15). */
  integrations(scanId: string): Observable<ScanIntegrations> {
    return this.http.get<ScanIntegrations>(`/api/v1/scans/${encodeURIComponent(scanId)}/integrations`);
  }

  /** Open ports and services (QUICK and STANDARD scans). */
  ports(scanId: string): Observable<OpenPort[]> {
    return this.http.get<OpenPort[]>(`/api/v1/scans/${encodeURIComponent(scanId)}/ports`);
  }
}

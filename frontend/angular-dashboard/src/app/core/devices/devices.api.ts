import { HttpClient } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { OpenPort } from '../scans/scans.api';

export const DEVICE_CATEGORIES = [
  'ROUTER', 'IP_CAMERA', 'SMART_TV', 'SMARTPHONE', 'TABLET', 'LAPTOP', 'DESKTOP', 'PRINTER', 'NAS', 'SMART_PLUG',
  'SMART_SPEAKER', 'IOT', 'UNKNOWN_DEVICE',
] as const;

export type DeviceCategory = (typeof DEVICE_CATEGORIES)[number];
export type Confidence = 'LOW' | 'MEDIUM' | 'HIGH';

/** Where a value comes from: the observation method, its reliability (L/M/H) and whether it agrees. */
export interface IdentificationSource {
  source: string;
  value: string;
  reliability: 'L' | 'M' | 'H';
  agrees: boolean;
}

export interface Identification {
  field: 'IP' | 'MAC' | 'HOSTNAME' | 'MANUFACTURER' | 'MODEL' | 'OS' | 'FIRMWARE' | 'DEVICE_TYPE';
  value: string;
  confidence: Confidence;
  sources: IdentificationSource[];
  conflict: boolean;
  scanId: string | null;
  identifiedAt: string;
}

export interface CategoryChange {
  source: 'AUTO' | 'MANUAL';
  oldCategory: string | null;
  newCategory: string | null;
  scanId: string | null;
  changedBy: string | null;
  changedAt: string;
}

/** Rule that matched: why a category was (or was not) chosen. */
export interface RuleMatch {
  rule: string;
  category: string;
  strength: 'STRONG' | 'MODERATE' | 'WEAK';
  sources: string[];
  values: string[];
}

/**
 * A device of the home inventory. {@code category} is the manual choice when set, otherwise
 * the detected one; {@code suggestedCategory} is a confident detection that disagrees with
 * the manual choice (never applied automatically).
 */
export interface Device {
  id: string;
  homeId: string;
  mac: string | null;
  macRandomized: boolean;
  probableSameAs: string | null;
  ip: string | null;
  addresses: string[];
  hostname: string | null;
  manufacturer: string | null;
  model: string | null;
  os: string | null;
  category: string;
  detectedCategory: string;
  detectedCategoryConfidence: Confidence | null;
  manualCategory: string | null;
  manualCategoryAt: string | null;
  suggestedCategory: string | null;
  overallConfidence: Confidence;
  rulesetVersion: string;
  classification: { matches?: RuleMatch[]; conflicts?: string[]; score?: number } | null;
  firstSeenAt: string;
  lastSeenAt: string;
  lastScanId: string | null;
  identifications: Identification[] | null;
  categoryHistory: CategoryChange[] | null;
  /** Last port scan of the device (detail only, null when its ports were never scanned). */
  services?: DeviceServices | null;
}

/** Counters of one port scan of a host: only the open ports are listed. */
export interface PortCounters {
  probed: number;
  open: number;
  closed: number;
  filtered: number;
  openFiltered: number;
  unknown: number;
}

export interface DeviceServices {
  scanId: string;
  scannedAt: string;
  summary: { profile?: string; listVersion?: string; tcp?: PortCounters; udp?: PortCounters; paused?: boolean };
  ports: OpenPort[];
  protocols: { protocol: string; confidence: Confidence; details: Record<string, unknown> }[];
}

@Injectable({ providedIn: 'root' })
export class DevicesApi {
  private readonly http = inject(HttpClient);

  list(homeId: string): Observable<Device[]> {
    return this.http.get<Device[]>(`/api/v1/homes/${encodeURIComponent(homeId)}/devices`);
  }

  get(deviceId: string): Observable<Device> {
    return this.http.get<Device>(`/api/v1/devices/${encodeURIComponent(deviceId)}`);
  }

  /** null clears the manual category: the detected one applies again. */
  classify(deviceId: string, category: string | null): Observable<Device> {
    return this.http.put<Device>(`/api/v1/devices/${encodeURIComponent(deviceId)}/category`, { category });
  }
}

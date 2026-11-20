import { HttpClient } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { OpenPort } from '../scans/scans.api';

export const DEVICE_CATEGORIES = [
  'ROUTER', 'IP_CAMERA', 'SMART_TV', 'SMARTPHONE', 'TABLET', 'LAPTOP', 'DESKTOP', 'PRINTER', 'NAS', 'SMART_PLUG',
  'SMART_SPEAKER', 'IOT', 'VOIP_PHONE', 'NETWORK_DEVICE', 'SERVER', 'UNKNOWN_DEVICE',
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
  /** Every MAC of the device (detail only, M19). */
  interfaces?: DeviceInterface[] | null;
  /** IPv4/IPv6 address history, most recently seen first (detail only, M19). */
  addressHistory?: DeviceAddress[] | null;
  /** Name given by the user (M20), never changed by scans. */
  customName?: string | null;
  /** customName, otherwise the host name. */
  displayName?: string | null;
  /** Fields of the device card with their status (detail only, M20). */
  identity?: IdentityField[] | null;
  /** Changes of value or status of the identity fields, newest first (detail only, M20). */
  identificationHistory?: IdentificationChange[] | null;
}

export type IdentityStatus = 'VERIFIED' | 'PROBABLE' | 'UNKNOWN';

/** Fields the user can confirm or correct (M20). */
export const CONFIRMABLE_FIELDS = ['MANUFACTURER', 'MODEL', 'PRODUCT_CODE', 'FIRMWARE', 'CPE', 'OS'];

export interface IdentityField {
  field: string;
  value: string | null;
  status: IdentityStatus;
  confidence: Confidence | null;
  /** Names of the agreeing sources (USER when confirmed by the user). */
  sources: string[];
  userConfirmed: boolean;
  conflict: boolean;
}

export interface IdentificationChange {
  field: string;
  oldValue: string | null;
  newValue: string | null;
  oldStatus: string | null;
  newStatus: string | null;
  origin: 'SCAN' | 'USER';
  scanId: string | null;
  changedAt: string;
}

/** One network interface (MAC) of a device; {@code current}: seen by the last scan of the device. */
export interface DeviceInterface {
  mac: string;
  macRandomized: boolean;
  vendor: string | null;
  agentInterface: string | null;
  current: boolean;
  firstSeenAt: string;
  lastSeenAt: string;
}

export type AddressScope = 'PRIVATE' | 'PUBLIC' | 'LINK_LOCAL' | 'LOOPBACK' | 'UNIQUE_LOCAL' | 'GLOBAL' | 'MULTICAST' | 'OTHER';

/** One address of the history; interfaceId EUI64 embeds the MAC, RANDOM is a temporary/privacy IPv6. */
export interface DeviceAddress {
  address: string;
  family: 4 | 6;
  scope: AddressScope | null;
  interfaceId: 'EUI64' | 'RANDOM' | null;
  eui64Mac: string | null;
  mac: string | null;
  current: boolean;
  firstSeenAt: string;
  lastSeenAt: string;
  timesSeen: number;
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

  /** Confirms or corrects a field of the card (M20); value null removes the confirmation. */
  confirmField(deviceId: string, field: string, value: string | null): Observable<Device> {
    return this.http.put<Device>(`/api/v1/devices/${encodeURIComponent(deviceId)}/identity`, { field, value });
  }

  /** Sets (or clears with null) the user's name of the device (M20). */
  rename(deviceId: string, name: string | null): Observable<Device> {
    return this.http.put<Device>(`/api/v1/devices/${encodeURIComponent(deviceId)}/name`, { name });
  }

  /** The user confirms that deviceId is the same physical device as intoDeviceId: returns the merged device. */
  merge(deviceId: string, intoDeviceId: string): Observable<Device> {
    return this.http.post<Device>(`/api/v1/devices/${encodeURIComponent(deviceId)}/merge`, { intoDeviceId });
  }

  /** The user says the two devices are different: the "probably the same device" hint goes away. */
  dismissSameAs(deviceId: string, otherDeviceId: string): Observable<Device> {
    return this.http.post<Device>(`/api/v1/devices/${encodeURIComponent(deviceId)}/same-as/dismiss`, { otherDeviceId });
  }
}

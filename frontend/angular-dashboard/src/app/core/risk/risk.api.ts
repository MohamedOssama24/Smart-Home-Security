import { HttpClient } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';

export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type RiskRating = 'EXCELLENT' | 'GOOD' | 'FAIR' | 'POOR' | 'CRITICAL';

export interface RiskDeduction {
  findingId: string;
  deviceId: string;
  ruleId: string;
  titleKey: string;
  params: Record<string, unknown>;
  severity: string;
  type: string;
  confidence: string;
  status: string;
  factors: { base: number; type: number; confidence: number; criticality: number; exposure: number; kev: number };
  value: number;
}

export interface RiskDevice {
  deviceId: string;
  name: string | null;
  ip: string | null;
  category: string | null;
  criticality: number;
  exposed: boolean;
  raw: number;
  applied: number;
  capped: boolean;
  findings: number;
}

export interface RiskExcluded {
  findingId: string;
  titleKey: string;
  params: Record<string, unknown>;
  severity: string;
  status: string;
}

export interface RiskDeltaFinding {
  findingId: string;
  titleKey: string | null;
  params: Record<string, unknown>;
  severity: string | null;
  value: number | null;
  status?: string;
}

export interface RiskDelta {
  previousSnapshotId: string;
  previousScanId: string;
  previousScore: number;
  scoreChange: number;
  coverageChange: number;
  newFindingsCount: number;
  newFindings: RiskDeltaFinding[];
  removedFindingsCount: number;
  removedFindings: RiskDeltaFinding[];
  newDevicesCount: number;
  newDevices: { deviceId: string; name: string | null; ip: string | null }[];
}

export interface CoverageDetail {
  profile: string;
  hostsDiscovered: number;
  hostsAnalyzed: number;
  hostRatio: number;
  depth: number;
  techniques: Record<string, boolean>;
  techniqueScore: number;
  routerIntegration: boolean;
  components: { hosts: number; depth: number; techniques: number; router: number };
}

/** A risk snapshot (docs/20-RISK-ENGINE.md): score is null after a DISCOVERY scan. */
export interface RiskSnapshot {
  id: string;
  homeId: string;
  scanId: string;
  scanProfile: string;
  trigger: 'SCAN' | 'TRIAGE';
  score: number | null;
  riskLevel: RiskLevel | null;
  rating: RiskRating | null;
  notComputedReason: string | null;
  coverage: number;
  coverageDetail: CoverageDetail;
  provisional: boolean;
  breakdown: {
    totalDeduction?: number;
    uncappedScore?: number | null;
    deviceCap?: number;
    provisionalCap?: number;
    deductionsCount?: number;
    deductions?: RiskDeduction[];
    devices?: RiskDevice[];
    excludedCount?: number;
    excluded?: RiskExcluded[];
    notScored?: number;
  };
  topDevices: RiskDevice[];
  delta: RiskDelta | null;
  computedAt: string;
  engineVersion: string;
}

export interface RiskOverview {
  current: RiskSnapshot | null;
  lastScored: RiskSnapshot | null;
}

export interface RiskHistoryEntry {
  id: string;
  scanId: string;
  scanProfile: string;
  trigger: 'SCAN' | 'TRIAGE';
  score: number | null;
  riskLevel: RiskLevel | null;
  rating: RiskRating | null;
  notComputedReason: string | null;
  coverage: number;
  provisional: boolean;
  scoreChange: number | null;
  computedAt: string;
  engineVersion: string;
}

@Injectable({ providedIn: 'root' })
export class RiskApi {
  private readonly http = inject(HttpClient);

  current(homeId: string): Observable<RiskOverview> {
    return this.http.get<RiskOverview>(`/api/v1/homes/${encodeURIComponent(homeId)}/risk`);
  }

  history(homeId: string): Observable<RiskHistoryEntry[]> {
    return this.http.get<RiskHistoryEntry[]>(`/api/v1/homes/${encodeURIComponent(homeId)}/risk/history`);
  }
}

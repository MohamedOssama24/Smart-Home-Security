import { HttpClient, HttpParams } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';

export const FINDING_STATUSES = ['OPEN', 'ACKNOWLEDGED', 'RESOLVED', 'FALSE_POSITIVE', 'ACCEPTED_RISK'] as const;
export const FINDING_SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL'] as const;
export const FINDING_TYPES = [
  'CONFIRMED_VULNERABILITY', 'POTENTIAL_RISK', 'SUSPICIOUS_CONFIGURATION', 'UNVERIFIED_INFORMATION',
] as const;
/** Statuses a user can set (RESOLVED is set only by a scan). */
export const TRIAGE_STATUSES = ['OPEN', 'ACKNOWLEDGED', 'FALSE_POSITIVE', 'ACCEPTED_RISK'] as const;

export type FindingStatus = (typeof FINDING_STATUSES)[number];
export type FindingSeverity = (typeof FINDING_SEVERITIES)[number];
export type FindingType = (typeof FINDING_TYPES)[number];

/**
 * A security finding of a home (docs/19-SECURITY-ANALYSIS.md). Title and recommendation are
 * i18n keys with their parameters: the backend never sends free text to display.
 */
export interface Finding {
  id: string;
  homeId: string;
  device: { id: string; name: string | null; ip: string | null; category: string | null };
  ruleId: string;
  ruleVersion: number;
  titleKey: string;
  recommendationKey: string;
  params: Record<string, unknown>;
  severity: FindingSeverity;
  type: FindingType;
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  source: string;
  protocol: string | null;
  port: number | null;
  cveId: string | null;
  status: FindingStatus;
  statusReason: string | null;
  statusChangedAt: string | null;
  firstDetectedAt: string;
  lastDetectedAt: string;
  resolvedAt: string | null;
  lastScanId: string | null;
}

export interface FindingEvidence {
  scanId: string | null;
  type: string;
  data: Record<string, unknown>;
  collectedAt: string;
}

/** A CVE linked to the finding, with how it matched the declared product. */
export interface MatchedCve {
  cveId: string;
  matchQuality: 'EXACT_VERSION' | 'VERSION_RANGE' | 'PRODUCT_ONLY';
  matchedCpe: string | null;
  product: string | null;
  version: string | null;
  severity: string | null;
  cvssScore: number | null;
  cvssVersion: string | null;
  description: string | null;
  kev: boolean;
  kevDateAdded: string | null;
  epssScore: number | null;
  epssPercentile: number | null;
}

export interface FindingDetail {
  finding: Finding;
  evidence: FindingEvidence[];
  vulnerabilities: MatchedCve[];
  matchedCves: number;
}

export interface FindingFilter {
  status?: string;
  severity?: string;
  type?: string;
}

/** A CVE matched to a device of the home (GET /homes/{id}/vulnerabilities). */
export interface HomeVulnerability {
  cveId: string;
  severity: string | null;
  cvssScore: number | null;
  kev: boolean;
  epssScore: number | null;
  matchQuality: MatchedCve['matchQuality'];
  product: string | null;
  version: string | null;
  device: { id: string; name: string | null; ip: string | null; category: string | null };
  findingId: string;
  findingStatus: string;
  findingType: string;
}

@Injectable({ providedIn: 'root' })
export class FindingsApi {
  private readonly http = inject(HttpClient);

  list(homeId: string, filter: FindingFilter = {}): Observable<Finding[]> {
    let params = new HttpParams();
    for (const [key, value] of Object.entries(filter)) {
      if (value) {
        params = params.set(key, value);
      }
    }
    return this.http.get<Finding[]>(`/api/v1/homes/${encodeURIComponent(homeId)}/findings`, { params });
  }

  get(id: string): Observable<FindingDetail> {
    return this.http.get<FindingDetail>(`/api/v1/findings/${encodeURIComponent(id)}`);
  }

  /** Reason mandatory except when reopening (OPEN). */
  changeStatus(id: string, status: string, reason: string | null): Observable<FindingDetail> {
    return this.http.patch<FindingDetail>(`/api/v1/findings/${encodeURIComponent(id)}/status`, { status, reason });
  }

  /** CVEs matched to the devices of the home, non-resolved findings only (at most 500). */
  homeVulnerabilities(homeId: string): Observable<HomeVulnerability[]> {
    return this.http.get<HomeVulnerability[]>(`/api/v1/homes/${encodeURIComponent(homeId)}/vulnerabilities`);
  }
}

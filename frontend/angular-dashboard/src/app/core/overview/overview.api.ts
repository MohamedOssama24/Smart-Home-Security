import { HttpClient } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { RiskLevel, RiskRating } from '../risk/risk.api';

/** Security figures of a home: null when the user cannot read its findings (finding:read). */
export interface HomeSecurity {
  /** Last computed score (null before the first Quick/Standard scan). */
  score: number | null;
  riskLevel: RiskLevel | null;
  rating: RiskRating | null;
  provisional: boolean;
  coverage: number | null;
  scoreChange: number | null;
  computedAt: string | null;
  /** Why the latest snapshot has no score (e.g. PORT_SCAN_REQUIRED after a Discovery scan). */
  notComputedReason: string | null;
  /** Counted findings (open or acknowledged) by severity. */
  openFindings: Partial<Record<'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL', number>>;
  kevFindings: number;
  devices: number;
  lastScanAt: string | null;
}

export interface HomeOverview {
  homeId: string;
  name: string;
  customerId: string | null;
  security: HomeSecurity | null;
}

@Injectable({ providedIn: 'root' })
export class OverviewApi {
  private readonly http = inject(HttpClient);

  /** Every home the user can read, with its figures (backend: GET /api/v1/overview). */
  list(): Observable<HomeOverview[]> {
    return this.http.get<HomeOverview[]>('/api/v1/overview');
  }
}

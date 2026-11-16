import { HttpClient } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';

/** Limits of the plan; {@code null} means unlimited. */
export interface Plan {
  code: string;
  maxHomes: number | null;
  maxUsers: number | null;
  maxCustomers: number | null;
  maxNetworksPerHome: number | null;
}

export interface Usage {
  homes: number;
  users: number;
  customers: number;
}

export interface TenantOverview {
  id: string;
  type: 'INDIVIDUAL' | 'BUSINESS' | 'PLATFORM';
  name: string;
  status: string;
  organizationId: string | null;
  plan: Plan;
  /** Only for users with tenant-wide read access. */
  usage: Usage | null;
}

export interface Organization {
  id: string;
  legalName: string;
  vatNumber: string | null;
  contactEmail: string | null;
  contactPhone: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface OrganizationData {
  legalName: string;
  vatNumber: string | null;
  contactEmail: string | null;
  contactPhone: string | null;
}

/** Current tenant, plan and organization (backend: /api/v1/tenants/current, /api/v1/organizations/current). */
@Injectable({ providedIn: 'root' })
export class TenancyApi {
  private readonly http = inject(HttpClient);

  current(): Observable<TenantOverview> {
    return this.http.get<TenantOverview>('/api/v1/tenants/current');
  }

  organization(): Observable<Organization> {
    return this.http.get<Organization>('/api/v1/organizations/current');
  }

  updateOrganization(data: OrganizationData): Observable<Organization> {
    return this.http.put<Organization>('/api/v1/organizations/current', data);
  }
}

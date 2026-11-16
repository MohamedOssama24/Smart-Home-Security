import { HttpClient } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';

export interface Customer {
  id: string;
  displayName: string;
  contactEmail: string | null;
  contactPhone: string | null;
  notes: string | null;
  createdAt: string;
  updatedAt: string;
}

/** Editable fields: PUT replaces all of them (omitted optional fields are cleared). */
export interface CustomerData {
  displayName: string;
  contactEmail: string | null;
  contactPhone: string | null;
  notes: string | null;
}

/** Customers of a business tenant (backend: /api/v1/customers). */
@Injectable({ providedIn: 'root' })
export class CustomersApi {
  private readonly http = inject(HttpClient);

  list(): Observable<Customer[]> {
    return this.http.get<Customer[]>('/api/v1/customers');
  }

  create(data: CustomerData): Observable<Customer> {
    return this.http.post<Customer>('/api/v1/customers', data);
  }

  update(id: string, data: CustomerData): Observable<Customer> {
    return this.http.put<Customer>(`/api/v1/customers/${encodeURIComponent(id)}`, data);
  }

  archive(id: string): Observable<void> {
    return this.http.delete<void>(`/api/v1/customers/${encodeURIComponent(id)}`);
  }
}

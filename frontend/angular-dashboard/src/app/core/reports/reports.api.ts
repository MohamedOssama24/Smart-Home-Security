import { HttpClient } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';

export type ReportStatus = 'PENDING' | 'READY' | 'FAILED';

/** PDF security report of a scan (generated in the background, then downloaded). */
export interface Report {
  id: string;
  homeId: string;
  scanId: string;
  locale: 'it' | 'en';
  status: ReportStatus;
  errorCode: string | null;
  sizeBytes: number | null;
  pages: number | null;
  sha256: string | null;
  requestedAt: string;
  generatedAt: string | null;
}

@Injectable({ providedIn: 'root' })
export class ReportsApi {
  private readonly http = inject(HttpClient);

  forHome(homeId: string): Observable<Report[]> {
    return this.http.get<Report[]>(`/api/v1/homes/${encodeURIComponent(homeId)}/reports`);
  }

  get(id: string): Observable<Report> {
    return this.http.get<Report>(`/api/v1/reports/${encodeURIComponent(id)}`);
  }

  /** 202: the report is PENDING until generated (report:generate on the home). */
  request(scanId: string, locale: 'it' | 'en'): Observable<Report> {
    return this.http.post<Report>(`/api/v1/scans/${encodeURIComponent(scanId)}/reports`, { locale });
  }

  /** The PDF, with the access token (a plain link would not carry it). */
  download(id: string): Observable<Blob> {
    return this.http.get(`/api/v1/reports/${encodeURIComponent(id)}/download`, { responseType: 'blob' });
  }
}

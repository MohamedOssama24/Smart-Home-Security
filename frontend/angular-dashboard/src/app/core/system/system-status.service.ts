import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, catchError, map, of, timeout } from 'rxjs';

export type BackendStatus = 'UP' | 'DOWN' | 'UNREACHABLE';

interface HealthResponse {
  status?: string;
}

/** Reads the public backend health probe exposed by Nginx at /healthz. */
@Injectable({ providedIn: 'root' })
export class SystemStatusService {
  private readonly http = inject(HttpClient);

  static readonly HEALTH_URL = '/healthz';
  static readonly TIMEOUT_MS = 5000;

  backendStatus(): Observable<BackendStatus> {
    return this.http.get<HealthResponse>(SystemStatusService.HEALTH_URL).pipe(
      timeout(SystemStatusService.TIMEOUT_MS),
      map((body): BackendStatus => (body?.status === 'UP' ? 'UP' : 'DOWN')),
      catchError((error: unknown) => of(SystemStatusService.statusFromError(error))),
    );
  }

  /** A 503 from Spring health means the backend answered but is not ready; anything else is unreachable. */
  private static statusFromError(error: unknown): BackendStatus {
    const status = (error as { status?: number } | null)?.status;
    return status === 503 ? 'DOWN' : 'UNREACHABLE';
  }
}

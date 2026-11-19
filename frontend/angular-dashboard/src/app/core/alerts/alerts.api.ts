import { HttpClient, HttpParams } from '@angular/common/http';
import { Injectable, inject, signal } from '@angular/core';
import { Observable } from 'rxjs';

export type AlertType = 'NEW_FINDING' | 'FINDING_RESOLVED' | 'SCORE_DROPPED' | 'NEW_DEVICE' | 'SCAN_FAILED' | 'AGENT_OFFLINE';
export type AlertSeverity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type AlertChannel = 'DASHBOARD' | 'EMAIL';

export const ALERT_TYPES: AlertType[] = ['NEW_FINDING', 'FINDING_RESOLVED', 'SCORE_DROPPED', 'NEW_DEVICE', 'SCAN_FAILED',
  'AGENT_OFFLINE'];
export const ALERT_SEVERITIES: AlertSeverity[] = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

/**
 * An alert of the user's inbox. The payload carries what the text needs (i18n keys of the
 * finding, score change, devices, scan failure reason, agent name), the same the e-mail uses.
 */
export interface Alert {
  id: string;
  homeId: string;
  homeName: string;
  deviceId: string | null;
  type: AlertType;
  severity: AlertSeverity;
  /** Times the same event happened while the alert was unresolved (deduplication). */
  occurrences: number;
  firstAt: string;
  lastAt: string;
  /** The condition ended (finding resolved, agent back online, score recovered...). */
  resolvedAt: string | null;
  readAt: string | null;
  payload: Record<string, any>;
}

export interface NotificationPreference {
  type: AlertType;
  channel: AlertChannel;
  enabled: boolean;
  minSeverity: AlertSeverity;
}

@Injectable({ providedIn: 'root' })
export class AlertsApi {
  private readonly http = inject(HttpClient);

  list(unreadOnly = false, limit = 100): Observable<Alert[]> {
    const params = new HttpParams().set('unread', unreadOnly).set('limit', limit);
    return this.http.get<Alert[]>('/api/v1/alerts', { params });
  }

  unreadCount(): Observable<{ count: number }> {
    return this.http.get<{ count: number }>('/api/v1/alerts/unread-count');
  }

  markRead(id: string): Observable<void> {
    return this.http.post<void>(`/api/v1/alerts/${encodeURIComponent(id)}/read`, null);
  }

  markAllRead(): Observable<{ count: number }> {
    return this.http.post<{ count: number }>('/api/v1/alerts/read-all', null);
  }

  /** Effective preferences: every type and channel (defaults when never saved). */
  preferences(): Observable<NotificationPreference[]> {
    return this.http.get<NotificationPreference[]>('/api/v1/notification-preferences');
  }

  savePreferences(items: NotificationPreference[]): Observable<NotificationPreference[]> {
    return this.http.put<NotificationPreference[]>('/api/v1/notification-preferences', { items });
  }
}

/** Unread alerts shown next to the menu entry; refreshed on navigation and after reading. */
@Injectable({ providedIn: 'root' })
export class UnreadAlerts {
  private readonly api = inject(AlertsApi);
  readonly count = signal(0);

  refresh(): void {
    this.api.unreadCount().subscribe({
      next: (r) => this.count.set(r.count),
      error: () => this.count.set(0), // a hint only: never blocks the page
    });
  }
}

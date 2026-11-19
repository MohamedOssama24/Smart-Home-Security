import { HttpClient } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';

/** A fact of the home the answer is based on: S1 score, F1… findings, D1… devices. */
export interface AssistantCitation {
  id: string;
  kind: 'SCORE' | 'FINDING' | 'DEVICE';
  label: string;
  severity: string | null;
  ip: string | null;
}

/** Answer of the read-only security assistant (Milestone 16): grounded in the home data only. */
export interface AssistantAnswer {
  answer: string;
  citations: AssistantCitation[];
  provider: string;
  fallback: boolean;
  fallbackReason: 'NOT_GROUNDED' | 'PROVIDER_UNAVAILABLE' | null;
  scanId: string | null;
  dataAsOf: string | null;
  generatedAt: string;
}

@Injectable({ providedIn: 'root' })
export class AssistantApi {
  private readonly http = inject(HttpClient);

  /** Nothing is stored: neither the question nor the answer (device:read + finding:read on the home). */
  ask(homeId: string, question: string, locale: 'it' | 'en'): Observable<AssistantAnswer> {
    return this.http.post<AssistantAnswer>(`/api/v1/homes/${encodeURIComponent(homeId)}/assistant/questions`, {
      question,
      locale,
    });
  }
}

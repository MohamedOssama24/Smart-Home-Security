import { HttpClient } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';

/** Association of a person with a device (M24): PROBABLE comes from an automatic source, CONFIRMED from a user. */
export interface PersonDevice {
  deviceId: string;
  status: 'PROBABLE' | 'CONFIRMED';
  source: 'USER' | 'DEVICE_NAME' | 'HOME_ASSISTANT' | 'DIRECTORY' | 'FIREWALL';
  evidence: string | null;
  updatedAt: string;
}

export interface Person {
  id: string;
  homeId: string;
  name: string;
  origin: string;
  createdAt: string;
  devices: PersonDevice[];
}

@Injectable({ providedIn: 'root' })
export class PeopleApi {
  private readonly http = inject(HttpClient);

  list(homeId: string): Observable<Person[]> {
    return this.http.get<Person[]>(`/api/v1/homes/${encodeURIComponent(homeId)}/people`);
  }

  create(homeId: string, name: string): Observable<Person> {
    return this.http.post<Person>(`/api/v1/homes/${encodeURIComponent(homeId)}/people`, { name });
  }

  rename(personId: string, name: string): Observable<Person> {
    return this.http.put<Person>(`/api/v1/people/${encodeURIComponent(personId)}`, { name });
  }

  /** Deletes the person and its associations. */
  remove(personId: string): Observable<void> {
    return this.http.delete<void>(`/api/v1/people/${encodeURIComponent(personId)}`);
  }

  /** Assigns the device to the person, or confirms a probable association. */
  assign(deviceId: string, personId: string): Observable<Person> {
    return this.http.put<Person>(`/api/v1/devices/${encodeURIComponent(deviceId)}/people/${encodeURIComponent(personId)}`, null);
  }

  /** Removes the association: it is not proposed again. */
  unassign(deviceId: string, personId: string): Observable<Person> {
    return this.http.delete<Person>(`/api/v1/devices/${encodeURIComponent(deviceId)}/people/${encodeURIComponent(personId)}`);
  }
}

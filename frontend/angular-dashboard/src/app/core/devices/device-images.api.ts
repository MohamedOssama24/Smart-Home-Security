import { HttpClient } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable, firstValueFrom } from 'rxjs';

/**
 * Device image (Milestone 23): DEVICE is the icon the device declares about itself (UPnP,
 * fetched by the agent), USER the photo uploaded by the user, shown first.
 */
export interface DeviceImage {
  deviceId: string;
  source: 'DEVICE' | 'USER';
  origin: 'UPNP' | 'UPLOAD';
  contentType: string;
  width: number | null;
  height: number | null;
  updatedAt: string;
  shown: boolean;
}

/** Accepted uploads (checked again by the backend on the content itself). */
export const IMAGE_UPLOAD_TYPES = ['image/png', 'image/jpeg'];
export const IMAGE_UPLOAD_MAX_BYTES = 1024 * 1024;

@Injectable({ providedIn: 'root' })
export class DeviceImagesApi {
  private readonly http = inject(HttpClient);

  /** The image shown for each device of the home that has one. */
  shownInHome(homeId: string): Observable<DeviceImage[]> {
    return this.http.get<DeviceImage[]>(`/api/v1/homes/${encodeURIComponent(homeId)}/device-images`);
  }

  ofDevice(deviceId: string): Observable<DeviceImage[]> {
    return this.http.get<DeviceImage[]>(`/api/v1/devices/${encodeURIComponent(deviceId)}/images`);
  }

  /** Image bytes: fetched with the session (an <img src> could not authenticate). */
  blob(deviceId: string, source?: 'DEVICE' | 'USER'): Observable<Blob> {
    const query = source ? `?source=${source}` : '';
    return this.http.get(`/api/v1/devices/${encodeURIComponent(deviceId)}/image${query}`, { responseType: 'blob' });
  }

  upload(deviceId: string, file: Blob): Observable<DeviceImage[]> {
    return this.http.put<DeviceImage[]>(`/api/v1/devices/${encodeURIComponent(deviceId)}/image`, file, {
      headers: { 'Content-Type': file.type || 'application/octet-stream' },
    });
  }

  remove(deviceId: string): Observable<DeviceImage[]> {
    return this.http.delete<DeviceImage[]>(`/api/v1/devices/${encodeURIComponent(deviceId)}/image`);
  }

  /**
   * Object URLs of the image shown for each device of the home (deviceId → URL). A missing or
   * unreadable image is skipped: the page shows the category icon instead. The caller revokes
   * the URLs ({@link revokeAll}) when it no longer needs them.
   */
  async loadShown(homeId: string): Promise<Map<string, string>> {
    const metas = await firstValueFrom(this.shownInHome(homeId));
    const entries = await Promise.all(metas.map(async (m) => {
      try {
        return [m.deviceId, URL.createObjectURL(await firstValueFrom(this.blob(m.deviceId)))] as const;
      } catch {
        return null;
      }
    }));
    return new Map(entries.filter((e): e is readonly [string, string] => e !== null));
  }
}

export function revokeAll(urls: Iterable<string>): void {
  for (const u of urls) {
    URL.revokeObjectURL(u);
  }
}

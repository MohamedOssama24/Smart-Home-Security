import { HttpTestingController, TestRequest } from '@angular/common/http/testing';

/**
 * Waits (macrotask by macrotask) until exactly one request for the URL is pending and returns it.
 * Needed because the auth code awaits other promises before issuing its HTTP calls.
 */
export async function nextRequest(http: HttpTestingController, url: string, attempts = 20): Promise<TestRequest> {
  for (let i = 0; i < attempts; i++) {
    const matches = http.match(url);
    if (matches.length === 1) {
      return matches[0];
    }
    if (matches.length > 1) {
      throw new Error(`Expected one request to ${url}, found ${matches.length}`);
    }
    await new Promise((resolve) => setTimeout(resolve));
  }
  throw new Error(`No request to ${url}`);
}

export const settle = () => new Promise((resolve) => setTimeout(resolve));

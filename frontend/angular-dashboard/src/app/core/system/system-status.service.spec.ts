import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { BackendStatus, SystemStatusService } from './system-status.service';

describe('SystemStatusService', () => {
  let service: SystemStatusService;
  let http: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({ providers: [provideHttpClient(), provideHttpClientTesting()] });
    service = TestBed.inject(SystemStatusService);
    http = TestBed.inject(HttpTestingController);
  });

  afterEach(() => http.verify());

  function check(respond: (req: ReturnType<HttpTestingController['expectOne']>) => void): BackendStatus | undefined {
    let result: BackendStatus | undefined;
    service.backendStatus().subscribe((status) => (result = status));
    respond(http.expectOne(SystemStatusService.HEALTH_URL));
    return result;
  }

  it('reports UP when the health probe says UP', () => {
    expect(check((req) => req.flush({ status: 'UP' }))).toBe('UP');
  });

  it('reports DOWN when the backend answers 503', () => {
    expect(check((req) => req.flush({ status: 'DOWN' }, { status: 503, statusText: 'Service Unavailable' }))).toBe('DOWN');
  });

  it('reports DOWN for an unexpected body', () => {
    expect(check((req) => req.flush({}))).toBe('DOWN');
  });

  it('reports UNREACHABLE on network or gateway errors', () => {
    expect(check((req) => req.error(new ProgressEvent('error')))).toBe('UNREACHABLE');
    expect(check((req) => req.flush('', { status: 502, statusText: 'Bad Gateway' }))).toBe('UNREACHABLE');
  });
});

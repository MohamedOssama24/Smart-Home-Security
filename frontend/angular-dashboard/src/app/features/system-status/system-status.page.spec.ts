import { TestBed } from '@angular/core/testing';
import { Subject } from 'rxjs';
import { BackendStatus, SystemStatusService } from '../../core/system/system-status.service';
import { translocoTesting } from '../../testing/transloco-testing';
import { SystemStatusPage } from './system-status.page';

describe('SystemStatusPage', () => {
  let responses: Subject<BackendStatus>;

  beforeEach(async () => {
    responses = new Subject<BackendStatus>();
    await TestBed.configureTestingModule({
      imports: [SystemStatusPage, translocoTesting()],
      providers: [{ provide: SystemStatusService, useValue: { backendStatus: () => responses } }],
    }).compileComponents();
  });

  function badgeText(element: HTMLElement): string {
    return element.querySelector('[data-testid="backend-status"]')?.textContent?.trim() ?? '';
  }

  it('shows the checking state, then the translated result', async () => {
    const fixture = TestBed.createComponent(SystemStatusPage);
    await fixture.whenStable();
    expect(badgeText(fixture.nativeElement)).toBe('Verifica in corso…');

    responses.next('UP');
    fixture.detectChanges();
    await fixture.whenStable();

    expect(badgeText(fixture.nativeElement)).toBe('Operativo');
  });

  it('shows the unreachable state', async () => {
    const fixture = TestBed.createComponent(SystemStatusPage);
    responses.next('UNREACHABLE');
    fixture.detectChanges();
    await fixture.whenStable();

    expect(badgeText(fixture.nativeElement)).toBe('Non raggiungibile');
  });
});

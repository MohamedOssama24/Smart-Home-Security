import { TestBed } from '@angular/core/testing';
import { HttpErrorResponse } from '@angular/common/http';
import { ActivatedRoute, provideRouter } from '@angular/router';
import { AuthService } from '../../core/auth/auth.service';
import { translocoTesting } from '../../testing/transloco-testing';
import { AcceptInvitationPage } from './accept-invitation.page';

describe('AcceptInvitationPage', () => {
  const auth = { acceptInvitation: vi.fn() };

  async function setup(fragment: string | null) {
    await TestBed.configureTestingModule({
      imports: [AcceptInvitationPage, translocoTesting()],
      providers: [
        provideRouter([]),
        { provide: AuthService, useValue: auth },
        { provide: ActivatedRoute, useValue: { snapshot: { fragment } } },
      ],
    }).compileComponents();
    const fixture = TestBed.createComponent(AcceptInvitationPage);
    await fixture.whenStable();
    return fixture;
  }

  beforeEach(() => vi.resetAllMocks());

  it('sets the password with the token taken from the fragment', async () => {
    auth.acceptInvitation.mockResolvedValue(undefined);
    const fixture = await setup('token=abcdefghijklmnop');
    fixture.componentInstance.form.setValue({ password: 'Lungo-e-sicuro-42!' });
    await fixture.componentInstance.submit();
    fixture.detectChanges();

    expect(auth.acceptInvitation).toHaveBeenCalledWith('abcdefghijklmnop', 'Lungo-e-sicuro-42!');
    expect((fixture.nativeElement as HTMLElement).querySelector('[data-testid="invitation-done"]')).not.toBeNull();
  });

  it('explains an expired or used link', async () => {
    auth.acceptInvitation.mockRejectedValue(new HttpErrorResponse({ status: 400, error: { code: 'INVALID_TOKEN' } }));
    const fixture = await setup('token=abcdefghijklmnop');
    fixture.componentInstance.form.setValue({ password: 'Lungo-e-sicuro-42!' });
    await fixture.componentInstance.submit();
    fixture.detectChanges();

    expect((fixture.nativeElement as HTMLElement).querySelector('[role="alert"]')?.textContent).toContain('non è valido');
  });

  it('does not submit without a valid token in the link', async () => {
    const fixture = await setup('token=<script>');
    fixture.detectChanges();
    expect((fixture.nativeElement as HTMLElement).querySelector('form')).toBeNull();
    await fixture.componentInstance.submit();
    expect(auth.acceptInvitation).not.toHaveBeenCalled();
  });
});

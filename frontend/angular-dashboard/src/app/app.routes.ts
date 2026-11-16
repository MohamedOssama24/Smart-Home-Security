import { Routes } from '@angular/router';
import { authGuard, guestGuard } from './core/auth/auth.guards';

export const routes: Routes = [
  { path: '', pathMatch: 'full', redirectTo: 'homes' },
  {
    path: 'login',
    canActivate: [guestGuard],
    loadComponent: () => import('./features/auth/login.page').then((m) => m.LoginPage),
  },
  {
    path: 'register',
    canActivate: [guestGuard],
    loadComponent: () => import('./features/auth/register.page').then((m) => m.RegisterPage),
  },
  {
    path: 'forgot-password',
    canActivate: [guestGuard],
    loadComponent: () => import('./features/auth/forgot-password.page').then((m) => m.ForgotPasswordPage),
  },
  {
    path: 'verify-email',
    loadComponent: () => import('./features/auth/verify-email.page').then((m) => m.VerifyEmailPage),
  },
  {
    path: 'reset-password',
    loadComponent: () => import('./features/auth/reset-password.page').then((m) => m.ResetPasswordPage),
  },
  {
    path: 'homes',
    canActivate: [authGuard],
    loadComponent: () => import('./features/homes/homes.page').then((m) => m.HomesPage),
  },
  {
    path: 'homes/:id',
    canActivate: [authGuard],
    loadComponent: () => import('./features/homes/home-detail.page').then((m) => m.HomeDetailPage),
  },
  {
    path: 'accept-invitation',
    loadComponent: () => import('./features/auth/accept-invitation.page').then((m) => m.AcceptInvitationPage),
  },
  {
    path: 'users',
    canActivate: [authGuard],
    loadComponent: () => import('./features/users/users.page').then((m) => m.UsersPage),
  },
  {
    path: 'customers',
    canActivate: [authGuard],
    loadComponent: () => import('./features/customers/customers.page').then((m) => m.CustomersPage),
  },
  {
    path: 'organization',
    canActivate: [authGuard],
    loadComponent: () => import('./features/organization/organization.page').then((m) => m.OrganizationPage),
  },
  {
    path: 'account',
    canActivate: [authGuard],
    loadComponent: () => import('./features/account/account.page').then((m) => m.AccountPage),
  },
  {
    path: 'system-status',
    loadComponent: () =>
      import('./features/system-status/system-status.page').then((m) => m.SystemStatusPage),
  },
  { path: '**', redirectTo: 'homes' },
];

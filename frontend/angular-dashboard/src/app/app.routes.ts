import { Routes } from '@angular/router';
import { authGuard, guestGuard } from './core/auth/auth.guards';

export const routes: Routes = [
  { path: '', pathMatch: 'full', redirectTo: 'overview' },
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
    path: 'homes/:id/scans',
    canActivate: [authGuard],
    loadComponent: () => import('./features/scans/scans.page').then((m) => m.ScansPage),
  },
  {
    path: 'homes/:id/devices',
    canActivate: [authGuard],
    loadComponent: () => import('./features/devices/devices.page').then((m) => m.DevicesPage),
  },
  {
    path: 'homes/:id/findings',
    canActivate: [authGuard],
    loadComponent: () => import('./features/findings/findings.page').then((m) => m.FindingsPage),
  },
  {
    path: 'homes/:id/risk',
    canActivate: [authGuard],
    loadComponent: () => import('./features/risk/risk.page').then((m) => m.RiskPage),
  },
  {
    path: 'overview',
    canActivate: [authGuard],
    loadComponent: () => import('./features/overview/overview.page').then((m) => m.OverviewPage),
  },
  {
    path: 'homes/:id/vulnerabilities',
    canActivate: [authGuard],
    loadComponent: () =>
      import('./features/vulnerabilities/vulnerabilities.page').then((m) => m.VulnerabilitiesPage),
  },
  {
    path: 'homes/:id/network-map',
    canActivate: [authGuard],
    loadComponent: () => import('./features/network-map/network-map.page').then((m) => m.NetworkMapPage),
  },
  {
    path: 'alerts',
    canActivate: [authGuard],
    loadComponent: () => import('./features/alerts/alerts.page').then((m) => m.AlertsPage),
  },
  {
    path: 'alerts/preferences',
    canActivate: [authGuard],
    loadComponent: () =>
      import('./features/alerts/alert-preferences.page').then((m) => m.AlertPreferencesPage),
  },
  {
    path: 'homes/:id/reports',
    canActivate: [authGuard],
    loadComponent: () => import('./features/reports/reports.page').then((m) => m.ReportsPage),
  },
  {
    path: 'homes/:id/assistant',
    canActivate: [authGuard],
    loadComponent: () => import('./features/assistant/assistant.page').then((m) => m.AssistantPage),
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
    path: 'billing',
    canActivate: [authGuard],
    loadComponent: () => import('./features/billing/billing.page').then((m) => m.BillingPage),
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

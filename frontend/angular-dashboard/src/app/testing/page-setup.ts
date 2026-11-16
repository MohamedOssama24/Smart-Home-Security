import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { Type, signal } from '@angular/core';
import { provideRouter } from '@angular/router';
import { Me } from '../core/auth/auth.models';
import { AuthService } from '../core/auth/auth.service';
import { ME } from './auth-fixtures';
import { translocoTesting } from './transloco-testing';

/** Organization administrator of a business tenant. */
export const ADMIN: Me = {
  ...ME,
  id: 'admin',
  tenant: { id: 't1', type: 'BUSINESS', name: 'Installatori Srl', organizationId: 'o1' },
  roles: [{ id: 'r1', role: 'ORGANIZATION_ADMIN', scopeType: 'TENANT', scopeId: null }],
  permissions: [
    'tenant:read', 'user:read', 'user:manage', 'role:manage', 'home:read', 'home:write', 'agent:read',
    'agent:enroll', 'agent:revoke', 'audit:read', 'organization:manage', 'customer:read', 'customer:manage',
    'network:manage', 'network:authorize',
  ],
};

/** Tenant-wide technician of the same business tenant. */
export const TECHNICIAN: Me = {
  ...ADMIN,
  id: 'tech',
  roles: [{ id: 'r2', role: 'TECHNICIAN', scopeType: 'TENANT', scopeId: null }],
  permissions: ['tenant:read', 'home:read', 'home:write', 'agent:read', 'agent:enroll', 'agent:revoke',
    'customer:read', 'network:manage', 'network:authorize'],
};

/** Creates a standalone page with a fake AuthService for the given user and real HTTP testing. */
export async function setupPage<T>(component: Type<T>, me: Me) {
  await TestBed.configureTestingModule({
    imports: [component, translocoTesting()],
    providers: [
      provideHttpClient(),
      provideHttpClientTesting(),
      provideRouter([]),
      {
        provide: AuthService,
        useValue: { me: signal(me), hasPermission: (p: string) => me.permissions.includes(p) },
      },
    ],
  }).compileComponents();
  const http = TestBed.inject(HttpTestingController);
  const fixture = TestBed.createComponent(component);
  fixture.detectChanges();
  return { fixture, http };
}

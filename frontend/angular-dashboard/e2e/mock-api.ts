import { Page } from '@playwright/test';

// [MOCK] API answers for the E2E tests: fictitious user, home, devices and CVEs (CVE-2099-*).
const NOW = '2026-11-18T09:00:00Z';

const ME = {
  id: 'u1', email: 'mock.user@example.test', displayName: 'Utente MOCK', locale: 'it', status: 'ACTIVE',
  emailVerifiedAt: NOW, tenant: { id: 't1', type: 'INDIVIDUAL', name: 'MOCK', organizationId: null },
  roles: [{ id: 'r1', role: 'CUSTOMER', scopeType: 'TENANT', scopeId: null }],
  permissions: ['home:read', 'home:write', 'agent:read', 'scan:read', 'scan:start', 'device:read', 'finding:read',
    'finding:triage', 'tenant:read'],
  sessionId: 's1',
};

const device = (id: string, ip: string, category: string, hostname: string) => ({
  id, homeId: 'h1', mac: null, macRandomized: false, probableSameAs: null, ip, addresses: [ip], hostname,
  manufacturer: 'MOCK', model: null, os: null, category, detectedCategory: category,
  detectedCategoryConfidence: 'HIGH', manualCategory: null, manualCategoryAt: null, suggestedCategory: null,
  overallConfidence: 'HIGH', rulesetVersion: '2026.11-1', classification: { matches: [] }, firstSeenAt: NOW,
  lastSeenAt: NOW, lastScanId: 's1', identifications: null, categoryHistory: null,
});

const DEVICES = [
  device('d1', '192.168.60.1', 'ROUTER', 'mock-router'),
  device('d2', '192.168.60.30', 'IP_CAMERA', 'mock-camera'),
  ...Array.from({ length: 12 }, (_, i) => device(`d${i + 3}`, `192.168.60.${50 + i}`, 'IOT', `mock-sensor-${i + 1}`)),
];

const riskDevice = (d: ReturnType<typeof device>, applied: number, exposed: boolean, findings: number) => ({
  deviceId: d.id, name: d.hostname, ip: d.ip, category: d.category, criticality: 1.3, exposed, raw: applied, applied,
  capped: false, findings,
});

const SNAPSHOT = {
  id: 'r1', homeId: 'h1', scanId: 's1', scanProfile: 'STANDARD', trigger: 'SCAN', score: 62, riskLevel: 'HIGH',
  rating: 'POOR', notComputedReason: null, coverage: 0.813, provisional: false,
  coverageDetail: { profile: 'STANDARD', hostsDiscovered: 14, hostsAnalyzed: 14, hostRatio: 1, depth: 0.85,
    techniques: { ARP: true, ICMP: true, MDNS: true, SSDP: true }, techniqueScore: 1, routerIntegration: false,
    components: { hosts: 0.4, depth: 0.213, techniques: 0.2, router: 0 } },
  breakdown: {
    totalDeduction: 38, uncappedScore: 62, deviceCap: 45, deductionsCount: 2, notScored: 0, excludedCount: 0,
    deductions: [
      { findingId: 'f1', deviceId: 'd2', ruleId: 'cve.version-match', titleKey: 'findings.rule.cve-version-match.title',
        params: { cve: 'CVE-2099-2001', product: 'MOCK rtspd', version: '1.0' }, severity: 'HIGH',
        type: 'CONFIRMED_VULNERABILITY', confidence: 'HIGH', status: 'OPEN',
        factors: { base: 15, type: 1, confidence: 1, criticality: 1.3, exposure: 1.5, kev: 1 }, value: 29.25 },
      { findingId: 'f2', deviceId: 'd1', ruleId: 'telnet.open', titleKey: 'findings.rule.telnet-open.title',
        params: { port: 23 }, severity: 'HIGH', type: 'SUSPICIOUS_CONFIGURATION', confidence: 'HIGH', status: 'OPEN',
        factors: { base: 15, type: 0.5, confidence: 1, criticality: 1.3, exposure: 1, kev: 1 }, value: 9.75 },
    ],
    devices: [riskDevice(DEVICES[1], 29.25, true, 1), riskDevice(DEVICES[0], 9.75, false, 1)],
    excluded: [],
  },
  topDevices: [riskDevice(DEVICES[1], 29.25, true, 1), riskDevice(DEVICES[0], 9.75, false, 1)],
  delta: null, computedAt: NOW, engineVersion: '2026.11-1',
};

const ROUTES: Record<string, unknown> = {
  'GET /api/v1/me': ME,
  'GET /api/v1/alerts/unread-count': { count: 2 },
  'GET /api/v1/overview': [
    { homeId: 'h1', name: 'Casa MOCK', customerId: null, security: { score: 62, riskLevel: 'HIGH', rating: 'POOR',
      provisional: false, coverage: 0.813, scoreChange: -5, computedAt: NOW, notComputedReason: null,
      openFindings: { HIGH: 2 }, kevFindings: 1, devices: 14, lastScanAt: NOW } },
    { homeId: 'h2', name: 'Seconda casa MOCK', customerId: null, security: { score: null, riskLevel: null,
      rating: null, provisional: false, coverage: null, scoreChange: null, computedAt: null, notComputedReason: null,
      openFindings: {}, kevFindings: 0, devices: 0, lastScanAt: null } },
  ],
  'GET /api/v1/homes/h1/risk': { current: SNAPSHOT, lastScored: SNAPSHOT },
  'GET /api/v1/homes/h1/risk/history': [
    { id: 'r1', scanId: 's1', scanProfile: 'STANDARD', trigger: 'SCAN', score: 62, riskLevel: 'HIGH', rating: 'POOR',
      notComputedReason: null, coverage: 0.813, provisional: false, scoreChange: null, computedAt: NOW,
      engineVersion: '2026.11-1' },
  ],
  'GET /api/v1/homes/h1/vulnerabilities': [
    { cveId: 'CVE-2099-2001', severity: 'HIGH', cvssScore: 8.1, kev: true, epssScore: 0.31,
      matchQuality: 'EXACT_VERSION', product: 'MOCK rtspd', version: '1.0',
      device: { id: 'd2', name: 'mock-camera', ip: '192.168.60.30', category: null }, findingId: 'f1',
      findingStatus: 'OPEN', findingType: 'CONFIRMED_VULNERABILITY' },
    { cveId: 'CVE-2099-2002', severity: 'MEDIUM', cvssScore: 5.0, kev: false, epssScore: null,
      matchQuality: 'VERSION_RANGE', product: 'MOCK httpd', version: '2.0',
      device: { id: 'd1', name: 'mock-router', ip: '192.168.60.1', category: null }, findingId: 'f3',
      findingStatus: 'OPEN', findingType: 'POTENTIAL_RISK' },
  ],
  'GET /api/v1/homes/h1/devices': DEVICES,
  'GET /api/v1/homes/h1/networks': [
    { id: 'n1', homeId: 'h1', name: 'Wi-Fi MOCK', cidr: '192.168.60.0/24', ipVersion: 4, kind: 'WIFI',
      source: 'MANUAL', authorized: true, authorization: null, createdAt: NOW, updatedAt: NOW },
  ],
};

/** Answers every /api call with [MOCK] data; collects the calls without an answer. */
export async function mockApi(page: Page): Promise<string[]> {
  const unexpected: string[] = [];
  await page.route('**/api/**', async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    const key = `${request.method()} ${path}`;
    if (key === 'GET /api/v1/auth/csrf') {
      await route.fulfill({ status: 204, headers: { 'set-cookie': 'XSRF-TOKEN=mock-csrf; Path=/; SameSite=Strict' } });
    } else if (key === 'POST /api/v1/auth/refresh') {
      await route.fulfill({ json: { accessToken: 'mock-access-token', tokenType: 'Bearer', expiresIn: 900,
        expiresAt: '2099-01-01T00:00:00Z', sessionId: 's1' } });
    } else if (key in ROUTES) {
      await route.fulfill({ json: ROUTES[key] });
    } else {
      unexpected.push(key);
      await route.fulfill({ status: 404, contentType: 'application/problem+json',
        json: { type: 'about:blank', title: 'Not Found', status: 404, code: 'NOT_FOUND' } });
    }
  });
  return unexpected;
}

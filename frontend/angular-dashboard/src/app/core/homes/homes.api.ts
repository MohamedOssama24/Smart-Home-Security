import { HttpClient } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';

export interface Home {
  id: string;
  name: string;
  customerId: string | null;
  address: string | null;
  timezone: string;
  createdAt: string;
  updatedAt: string;
}

/** Editable fields of a home: PUT replaces all of them (omitted optional fields are cleared). */
export interface HomeData {
  name: string;
  customerId: string | null;
  address: string | null;
  timezone: string | null;
}

export type NetworkKind = 'ETHERNET' | 'WIFI' | 'VLAN' | 'GUEST' | 'UNKNOWN';
export const NETWORK_KINDS: readonly NetworkKind[] = ['WIFI', 'ETHERNET', 'VLAN', 'GUEST', 'UNKNOWN'];

/**
 * Version of the attestation text the user confirms to authorize a network (i18n key
 * "networks.attestation.v1"). Must match the backend: a different version is refused.
 */
export const ATTESTATION_VERSION = '1';

export interface NetworkAuthorization {
  authorizedBy: string;
  authorizedAt: string;
  attestationVersion: string;
}

export interface Network {
  id: string;
  homeId: string;
  name: string;
  cidr: string;
  ipVersion: 4 | 6;
  kind: NetworkKind;
  source: 'MANUAL';
  authorized: boolean;
  authorization: NetworkAuthorization | null;
  createdAt: string;
  updatedAt: string;
}

export type EnrollmentTokenState = 'ACTIVE' | 'USED' | 'EXPIRED' | 'REVOKED';

export interface EnrollmentToken {
  id: string;
  homeId: string;
  state: EnrollmentTokenState;
  createdAt: string;
  expiresAt: string;
  usedAt: string | null;
  usedByAgentId: string | null;
}

/** Returned only once by the backend: the clear token is never shown again. */
export interface CreatedEnrollmentToken {
  id: string;
  homeId: string;
  token: string;
  expiresAt: string;
}

export interface Agent {
  id: string;
  homeId: string;
  name: string;
  hostname: string | null;
  os: string;
  arch: string;
  agentVersion: string;
  status: 'ACTIVE' | 'REVOKED';
  enrolledAt: string;
  lastSeenAt: string | null;
  revokedAt: string | null;
  revokeReason: string | null;
  /** Computed by the backend from the last heartbeat (online < 3 min, stale < 15 min). */
  connectivity: AgentConnectivity;
  lastHeartbeatAt: string | null;
  /** Self-diagnosis of the last heartbeat (null before the first one). */
  capabilities: AgentCapabilities | null;
  interfaces: AgentInterface[] | null;
  queueDepth: number | null;
  uptimeSeconds: number | null;
  lastError: string | null;
}

export type AgentConnectivity = 'ONLINE' | 'STALE' | 'OFFLINE' | 'NEVER_CONNECTED' | 'REVOKED';

export interface AgentCapabilities {
  privileged: boolean;
  arp: 'raw' | 'os_api' | 'os_table' | 'unavailable';
  icmp: 'raw' | 'unprivileged' | 'os_api' | 'unavailable';
  /** Codes such as ARP_TABLE_ONLY, translated in agents.warning.* */
  warnings: string[];
  /** Router integrations configured on the agent (names only, never settings); absent before M7. */
  routerIntegrations?: ('TR064' | 'SNMP')[] | null;
}

export interface AgentInterface {
  name: string;
  mac?: string;
  mtu: number;
  addresses: string[];
}

/** Event delivered by the agent from its local queue. */
export interface AgentEvent {
  id: string;
  type: string;
  occurredAt: string;
  receivedAt: string;
  detail: Record<string, unknown>;
}

@Injectable({ providedIn: 'root' })
export class HomesApi {
  private readonly http = inject(HttpClient);

  list(customerId?: string): Observable<Home[]> {
    return this.http.get<Home[]>('/api/v1/homes', customerId ? { params: { customerId } } : {});
  }

  get(id: string): Observable<Home> {
    return this.http.get<Home>(`/api/v1/homes/${encodeURIComponent(id)}`);
  }

  create(data: HomeData): Observable<Home> {
    return this.http.post<Home>('/api/v1/homes', data);
  }

  update(id: string, data: HomeData): Observable<Home> {
    return this.http.put<Home>(`/api/v1/homes/${encodeURIComponent(id)}`, data);
  }

  /** Archives the home (refused while it still has active agents). */
  archive(id: string): Observable<void> {
    return this.http.delete<void>(`/api/v1/homes/${encodeURIComponent(id)}`);
  }

  networks(homeId: string): Observable<Network[]> {
    return this.http.get<Network[]>(`/api/v1/homes/${encodeURIComponent(homeId)}/networks`);
  }

  createNetwork(homeId: string, data: { name: string; cidr: string; kind: NetworkKind }): Observable<Network> {
    return this.http.post<Network>(`/api/v1/homes/${encodeURIComponent(homeId)}/networks`, data);
  }

  updateNetwork(networkId: string, data: { name: string; kind: NetworkKind }): Observable<Network> {
    return this.http.put<Network>(`/api/v1/networks/${encodeURIComponent(networkId)}`, data);
  }

  deleteNetwork(networkId: string): Observable<void> {
    return this.http.delete<void>(`/api/v1/networks/${encodeURIComponent(networkId)}`);
  }

  /** Records the user's explicit attestation: it never starts a scan. */
  authorizeNetwork(networkId: string): Observable<Network> {
    return this.http.post<Network>(`/api/v1/networks/${encodeURIComponent(networkId)}/authorization`, {
      attestation: true,
      attestationVersion: ATTESTATION_VERSION,
    });
  }

  revokeNetworkAuthorization(networkId: string): Observable<Network> {
    return this.http.delete<Network>(`/api/v1/networks/${encodeURIComponent(networkId)}/authorization`);
  }

  enrollmentTokens(homeId: string): Observable<EnrollmentToken[]> {
    return this.http.get<EnrollmentToken[]>(`/api/v1/homes/${encodeURIComponent(homeId)}/agent-enrollment-tokens`);
  }

  createEnrollmentToken(homeId: string): Observable<CreatedEnrollmentToken> {
    return this.http.post<CreatedEnrollmentToken>(
      `/api/v1/homes/${encodeURIComponent(homeId)}/agent-enrollment-tokens`,
      {},
    );
  }

  revokeEnrollmentToken(tokenId: string): Observable<void> {
    return this.http.delete<void>(`/api/v1/agent-enrollment-tokens/${encodeURIComponent(tokenId)}`);
  }

  agents(homeId: string): Observable<Agent[]> {
    return this.http.get<Agent[]>(`/api/v1/homes/${encodeURIComponent(homeId)}/agents`);
  }

  revokeAgent(agentId: string, reason: string): Observable<Agent> {
    return this.http.post<Agent>(`/api/v1/agents/${encodeURIComponent(agentId)}/revoke`, { reason });
  }

  agentEvents(agentId: string): Observable<AgentEvent[]> {
    return this.http.get<AgentEvent[]>(`/api/v1/agents/${encodeURIComponent(agentId)}/events`);
  }
}

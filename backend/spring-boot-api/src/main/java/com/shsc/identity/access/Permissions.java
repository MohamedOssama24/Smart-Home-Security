package com.shsc.identity.access;

/** Permission codes (catalogue seeded by migration V002, table {@code permissions}). */
public final class Permissions {

    public static final String PLATFORM_ADMIN = "platform:admin";
    public static final String TENANT_READ = "tenant:read";
    public static final String USER_READ = "user:read";
    public static final String USER_MANAGE = "user:manage";
    public static final String ROLE_MANAGE = "role:manage";
    public static final String HOME_READ = "home:read";
    public static final String HOME_WRITE = "home:write";
    public static final String AGENT_READ = "agent:read";
    public static final String AGENT_ENROLL = "agent:enroll";
    public static final String AGENT_REVOKE = "agent:revoke";
    public static final String AUDIT_READ = "audit:read";
    public static final String ORGANIZATION_MANAGE = "organization:manage";
    public static final String CUSTOMER_READ = "customer:read";
    public static final String CUSTOMER_MANAGE = "customer:manage";
    public static final String NETWORK_MANAGE = "network:manage";
    public static final String NETWORK_AUTHORIZE = "network:authorize";

    private Permissions() {
    }
}

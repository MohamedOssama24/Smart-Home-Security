package com.shsc.tenancy;

import java.util.Map;
import java.util.UUID;

import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Component;

import com.shsc.shared.web.ApiException;
import com.shsc.tenancy.TenantRepository.Tenant;

/**
 * Limits of the tenant's plan (only FREE exists until the SaaS milestone). Every check
 * locks the tenant row first, so concurrent creations are serialized and cannot exceed a
 * limit together. Must be called inside the transaction that creates the resource.
 * Archived homes/customers and disabled users do not count.
 */
@Component
public class PlanLimits {

    public enum Resource { HOMES, USERS, CUSTOMERS, NETWORKS_PER_HOME }

    /** Limits of a plan; {@code null} means unlimited. */
    public record Plan(String code, Integer maxHomes, Integer maxUsers, Integer maxCustomers,
            Integer maxNetworksPerHome) {

        Integer max(Resource resource) {
            return switch (resource) {
                case HOMES -> maxHomes;
                case USERS -> maxUsers;
                case CUSTOMERS -> maxCustomers;
                case NETWORKS_PER_HOME -> maxNetworksPerHome;
            };
        }
    }

    public record Usage(int homes, int users, int customers) {
    }

    private final JdbcClient jdbc;
    private final TenantRepository tenants;

    public PlanLimits(JdbcClient jdbc, TenantRepository tenants) {
        this.jdbc = jdbc;
        this.tenants = tenants;
    }

    public Plan planOf(Tenant tenant) {
        return jdbc.sql("""
                SELECT code, max_homes, max_users, max_customers, max_networks_per_home
                FROM plans WHERE code = :code""")
                .param("code", tenant.planCode())
                .query((rs, n) -> new Plan(rs.getString("code"), rs.getObject("max_homes", Integer.class),
                        rs.getObject("max_users", Integer.class), rs.getObject("max_customers", Integer.class),
                        rs.getObject("max_networks_per_home", Integer.class)))
                .single();
    }

    public Usage usage() {
        return new Usage(count(Resource.HOMES, null), count(Resource.USERS, null), count(Resource.CUSTOMERS, null));
    }

    /**
     * Throws 409 {@code PLAN_LIMIT_REACHED} when adding one more {@code resource} would exceed
     * the plan. {@code homeId} is required for {@link Resource#NETWORKS_PER_HOME}.
     */
    public void requireCapacity(Resource resource, UUID homeId) {
        Tenant tenant = tenants.lockCurrent().orElseThrow(ApiException::notFound);
        Integer max = planOf(tenant).max(resource);
        if (max != null && count(resource, homeId) >= max) {
            throw new ApiException(HttpStatus.CONFLICT, "PLAN_LIMIT_REACHED",
                    "The limit of your plan for this resource has been reached.",
                    Map.of("resource", resource.name(), "limit", max, "plan", tenant.planCode()));
        }
    }

    private int count(Resource resource, UUID homeId) {
        String sql = switch (resource) {
            case HOMES -> "SELECT count(*) FROM homes WHERE archived_at IS NULL";
            case USERS -> "SELECT count(*) FROM users WHERE status <> 'DISABLED'";
            case CUSTOMERS -> "SELECT count(*) FROM customers WHERE archived_at IS NULL";
            case NETWORKS_PER_HOME -> "SELECT count(*) FROM networks WHERE home_id = :home";
        };
        var statement = jdbc.sql(sql);
        if (resource == Resource.NETWORKS_PER_HOME) {
            statement = statement.param("home", homeId);
        }
        return statement.query(Integer.class).single();
    }
}

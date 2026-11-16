package com.shsc.identity.access;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionTemplate;

import com.shsc.identity.access.RoleAssignment.ScopeType;

/**
 * Role → permissions catalogue, loaded once from the reference tables (read-only for the
 * runtime role; changed only by migrations).
 */
@Component
public class RoleCatalog {

    public record RoleDefinition(String code, String description, Set<ScopeType> assignableScopes,
            Set<String> permissions) {
    }

    private final Map<String, RoleDefinition> roles;

    public RoleCatalog(JdbcClient jdbc, TransactionTemplate tx) {
        Map<String, Set<String>> permissions = new LinkedHashMap<>();
        Map<String, RoleDefinition> loaded = new LinkedHashMap<>();
        tx.executeWithoutResult(status -> {
            jdbc.sql("SELECT role_code, permission_code FROM role_permissions ORDER BY role_code, permission_code")
                    .query(rs -> {
                        permissions.computeIfAbsent(rs.getString(1), k -> new TreeSet<>()).add(rs.getString(2));
                    });
            jdbc.sql("SELECT code, description, assignable_scopes FROM roles ORDER BY code").query(rs -> {
                String code = rs.getString("code");
                String[] scopes = (String[]) rs.getArray("assignable_scopes").getArray();
                Set<ScopeType> scopeTypes = new TreeSet<>(Arrays.stream(scopes).map(ScopeType::valueOf).toList());
                loaded.put(code, new RoleDefinition(code, rs.getString("description"),
                        Collections.unmodifiableSet(scopeTypes),
                        Collections.unmodifiableSet(permissions.getOrDefault(code, Set.of()))));
            });
        });
        this.roles = Collections.unmodifiableMap(loaded);
    }

    public List<RoleDefinition> all() {
        return new ArrayList<>(roles.values());
    }

    public RoleDefinition find(String code) {
        return roles.get(code);
    }

    public Set<String> permissionsOf(String roleCode) {
        RoleDefinition role = roles.get(roleCode);
        return role == null ? Set.of() : role.permissions();
    }
}

package com.shsc.identity.user;

import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.shsc.identity.access.RoleAssignment.ScopeType;
import com.shsc.identity.access.RoleCatalog.RoleDefinition;
import com.shsc.identity.authentication.AuthThrottle;
import com.shsc.identity.role.RoleAssignmentRepository.StoredAssignment;
import com.shsc.identity.role.RoleService;
import com.shsc.identity.user.UserService.Invitation;
import com.shsc.identity.user.UserService.UserView;
import com.shsc.shared.web.ClientInfo;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/** Users of the tenant (invitation, update, enable/disable) and their role assignments. */
@RestController
public class UserController {

    private static final String INVITE = "invite";

    public record UserSummary(UUID id, String email, String displayName, String locale, String status,
            boolean invitationPending, Instant createdAt, Instant lastLoginAt, List<AssignmentResponse> roles) {
        static UserSummary of(UserView view) {
            UserRecord u = view.user();
            return new UserSummary(u.id(), u.email(), u.displayName(), u.locale(), u.status().name(),
                    view.invitationPending(), u.createdAt(), u.lastLoginAt(),
                    view.roles().stream().map(AssignmentResponse::of).toList());
        }
    }

    public record InviteRequest(
            @NotBlank @Email @Size(max = 254) String email,
            @NotBlank @Size(max = 100) String displayName,
            @Pattern(regexp = "it|en") String locale,
            @NotBlank @Size(max = 50) String role,
            @NotNull ScopeType scopeType,
            UUID scopeId) {
    }

    /** Partial update: {@code null} fields are left unchanged. */
    public record UpdateUserRequest(@Size(min = 1, max = 100) String displayName,
            @Pattern(regexp = "ACTIVE|DISABLED") String status) {
    }

    public record AssignRoleRequest(@NotBlank @Size(max = 50) String role, @NotNull ScopeType scopeType,
            UUID scopeId) {
    }

    public record AssignmentResponse(UUID id, String role, ScopeType scopeType, UUID scopeId, UUID grantedBy,
            Instant grantedAt) {
        static AssignmentResponse of(StoredAssignment a) {
            return new AssignmentResponse(a.assignment().id(), a.assignment().role(), a.assignment().scopeType(),
                    a.assignment().scopeId(), a.grantedBy(), a.grantedAt());
        }
    }

    public record RoleResponse(String code, String description, Set<ScopeType> assignableScopes,
            Set<String> permissions) {
    }

    public record CreatedAssignment(UUID id) {
    }

    private final UserService users;
    private final RoleService roles;
    private final AuthThrottle throttle;

    public UserController(UserService users, RoleService roles, AuthThrottle throttle) {
        this.users = users;
        this.roles = roles;
        this.throttle = throttle;
    }

    @GetMapping("/api/v1/users")
    public List<UserSummary> list() {
        return users.list().stream().map(UserSummary::of).toList();
    }

    @GetMapping("/api/v1/users/{userId}")
    public UserSummary get(@PathVariable UUID userId) {
        return UserSummary.of(users.get(userId));
    }

    /** Invites a user into the tenant with a first role; the user chooses the password. */
    @PostMapping("/api/v1/users")
    public ResponseEntity<UserSummary> invite(@Valid @RequestBody InviteRequest request, HttpServletRequest http) {
        ClientInfo client = ClientInfo.from(http);
        // e-mail sending is rate limited like the public e-mail endpoints
        throttle.consumeMailQuota(AuthThrottle.ipKey(INVITE, client.ip()),
                AuthThrottle.accountKey(INVITE, request.email().trim().toLowerCase(java.util.Locale.ROOT)));
        UserView user = users.invite(new Invitation(request.email(), request.displayName(), request.locale(),
                request.role(), request.scopeType(), request.scopeId()), client);
        return ResponseEntity.created(URI.create("/api/v1/users/" + user.user().id())).body(UserSummary.of(user));
    }

    @PostMapping("/api/v1/users/{userId}/invitation")
    @ResponseStatus(HttpStatus.ACCEPTED)
    public void resendInvitation(@PathVariable UUID userId, HttpServletRequest http) {
        ClientInfo client = ClientInfo.from(http);
        throttle.consumeMailQuota(AuthThrottle.ipKey(INVITE, client.ip()),
                AuthThrottle.accountKey(INVITE, userId.toString()));
        users.resendInvitation(userId, client);
    }

    @PatchMapping("/api/v1/users/{userId}")
    public UserSummary update(@PathVariable UUID userId, @Valid @RequestBody UpdateUserRequest request,
            HttpServletRequest http) {
        UserRecord.Status status = request.status() == null ? null : UserRecord.Status.valueOf(request.status());
        String displayName = request.displayName() == null || request.displayName().isBlank() ? null
                : request.displayName();
        return UserSummary.of(users.update(userId, displayName, status, ClientInfo.from(http)));
    }

    @GetMapping("/api/v1/roles")
    public List<RoleResponse> catalogue() {
        return roles.catalogue().stream()
                .filter(r -> !r.assignableScopes().contains(ScopeType.PLATFORM))
                .map(UserController::toResponse).toList();
    }

    @GetMapping("/api/v1/users/{userId}/roles")
    public List<AssignmentResponse> assignments(@PathVariable UUID userId) {
        return roles.list(userId).stream().map(AssignmentResponse::of).toList();
    }

    @PostMapping("/api/v1/users/{userId}/roles")
    @ResponseStatus(HttpStatus.CREATED)
    public CreatedAssignment assign(@PathVariable UUID userId, @Valid @RequestBody AssignRoleRequest request,
            HttpServletRequest http) {
        return new CreatedAssignment(roles.assign(userId, request.role(), request.scopeType(), request.scopeId(),
                ClientInfo.from(http)));
    }

    @DeleteMapping("/api/v1/users/{userId}/roles/{assignmentId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void revoke(@PathVariable UUID userId, @PathVariable UUID assignmentId, HttpServletRequest http) {
        roles.revoke(userId, assignmentId, ClientInfo.from(http));
    }

    private static RoleResponse toResponse(RoleDefinition role) {
        return new RoleResponse(role.code(), role.description(), role.assignableScopes(), role.permissions());
    }
}

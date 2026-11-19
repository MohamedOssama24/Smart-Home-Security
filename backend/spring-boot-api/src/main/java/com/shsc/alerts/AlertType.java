package com.shsc.alerts;

import java.util.List;

import com.shsc.identity.access.Permissions;

/**
 * Alert types (docs/22-ALERTS-REPORTS.md §1) and the permission a user needs on the home to receive
 * and see them: the alert repeats information the user could read in the dashboard.
 */
public enum AlertType {
    NEW_FINDING(Permissions.FINDING_READ),
    FINDING_RESOLVED(Permissions.FINDING_READ),
    SCORE_DROPPED(Permissions.FINDING_READ),
    NEW_DEVICE(Permissions.DEVICE_READ),
    SCAN_FAILED(Permissions.SCAN_READ),
    AGENT_OFFLINE(Permissions.AGENT_READ);

    /** PUSH: the mobile app (FCM), only for users with a registered device and when FCM is configured. */
    public enum Channel { DASHBOARD, EMAIL, PUSH }

    /** Ordered from the least to the most severe. */
    public static final List<String> SEVERITIES = List.of("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL");

    private final String permission;

    AlertType(String permission) {
        this.permission = permission;
    }

    public String permission() {
        return permission;
    }

    public static int rank(String severity) {
        return SEVERITIES.indexOf(severity);
    }

    /** Defaults without a saved preference: everything on the dashboard, e-mail and push from MEDIUM up. */
    public static String defaultMinSeverity(Channel channel) {
        return channel == Channel.DASHBOARD ? "INFO" : "MEDIUM";
    }
}

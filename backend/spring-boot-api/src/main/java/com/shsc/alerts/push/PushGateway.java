package com.shsc.alerts.push;

import java.util.Map;

/** Sends one notification to one app installation (FCM in production, a fake in tests). */
public interface PushGateway {

    enum Result {
        SENT,
        /** The token is no longer valid (app uninstalled, token rotated): the device is removed. */
        INVALID_TOKEN,
        /** Temporary error: the delivery is retried. */
        FAILED
    }

    /** False when push is not configured: no PUSH delivery is created. */
    boolean enabled();

    /** {@code data} carries only identifiers (alert, home, type), never evidence or personal data. */
    Result send(String token, String title, String body, Map<String, String> data);
}

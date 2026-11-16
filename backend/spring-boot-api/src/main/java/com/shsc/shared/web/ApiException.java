package com.shsc.shared.web;

import java.time.Duration;
import java.util.Map;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.ErrorResponseException;

/**
 * Business error rendered as RFC 9457 Problem Details with a stable machine-readable
 * {@code code}. Messages never contain secrets or internal details.
 */
public class ApiException extends ErrorResponseException {

    private final String code;

    public ApiException(HttpStatus status, String code, String detail) {
        this(status, code, detail, Map.of());
    }

    public ApiException(HttpStatus status, String code, String detail, Map<String, Object> properties) {
        super(status, problem(status, code, detail, properties), null);
        this.code = code;
    }

    public String getCode() {
        return code;
    }

    public static ProblemDetail problem(HttpStatus status, String code, String detail,
            Map<String, Object> properties) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(status, detail);
        problem.setProperty("code", code);
        properties.forEach(problem::setProperty);
        return problem;
    }

    public static ApiException notFound() {
        return new ApiException(HttpStatus.NOT_FOUND, "NOT_FOUND", "The requested resource does not exist.");
    }

    public static ApiException forbidden() {
        return new ApiException(HttpStatus.FORBIDDEN, "FORBIDDEN", "You are not allowed to perform this operation.");
    }

    public static ApiException badRequest(String code, String detail) {
        return new ApiException(HttpStatus.BAD_REQUEST, code, detail);
    }

    public static ApiException unauthorized(String code, String detail) {
        return new ApiException(HttpStatus.UNAUTHORIZED, code, detail);
    }

    public static ApiException conflict(String code, String detail) {
        return new ApiException(HttpStatus.CONFLICT, code, detail);
    }

    public static ApiException tooManyRequests(Duration retryAfter) {
        ApiException exception = new ApiException(HttpStatus.TOO_MANY_REQUESTS, "TOO_MANY_ATTEMPTS",
                "Too many attempts. Try again later.",
                Map.of("retryAfterSeconds", Math.max(1, retryAfter.toSeconds())));
        exception.getHeaders().set(HttpHeaders.RETRY_AFTER, Long.toString(Math.max(1, retryAfter.toSeconds())));
        return exception;
    }
}

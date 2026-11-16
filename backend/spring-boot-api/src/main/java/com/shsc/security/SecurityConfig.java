package com.shsc.security;

import java.time.Duration;
import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.shsc.agents.auth.AgentAuthService;
import com.shsc.agents.auth.AgentAuthenticationFilter;
import com.shsc.agents.auth.AgentPrincipal;
import com.shsc.identity.access.UserJwtAuthenticationConverter;
import com.shsc.shared.config.ShscProperties;

/**
 * Three filter chains:
 * <ol>
 * <li>{@code /api/v1/agent/**}: agent tokens only, stateless, no cookies, no CORS;</li>
 * <li>{@code /api/**}: user ES256 access tokens (Bearer). CSRF double-submit protection on
 * the cookie-based auth endpoints ({@code POST /api/v1/auth/**});</li>
 * <li>everything else: health probes and (when enabled) API docs; all other paths denied.</li>
 * </ol>
 * HSTS, frame and content-type headers are set by Nginx (single source, no duplicates);
 * Spring keeps {@code Cache-Control: no-store} on API responses.
 */
@Configuration(proxyBeanMethods = false)
@EnableWebSecurity
public class SecurityConfig {

    static final String[] PUBLIC_AUTH_POSTS = {
        "/api/v1/auth/register", "/api/v1/auth/login", "/api/v1/auth/refresh", "/api/v1/auth/logout",
        "/api/v1/auth/verify-email", "/api/v1/auth/verify-email/resend",
        "/api/v1/auth/password/forgot", "/api/v1/auth/password/reset", "/api/v1/auth/invitation/accept"
    };

    /** CSRF is enforced on state-changing requests that may carry the refresh cookie. */
    static final RequestMatcher COOKIE_ENDPOINTS = request -> !"GET".equals(request.getMethod())
            && !"HEAD".equals(request.getMethod()) && !"OPTIONS".equals(request.getMethod())
            && request.getRequestURI().startsWith("/api/v1/auth/");

    @Bean
    @Order(1)
    SecurityFilterChain agentApi(HttpSecurity http, AgentAuthService agentAuth, ProblemResponses problems)
            throws Exception {
        http.securityMatcher("/api/v1/agent/**")
                .csrf(AbstractHttpConfigurer::disable)
                .cors(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable)
                .requestCache(AbstractHttpConfigurer::disable)
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .headers(SecurityConfig::headers)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.POST, "/api/v1/agent/enroll", "/api/v1/agent/token").permitAll()
                        .anyRequest().hasAuthority(AgentPrincipal.ROLE))
                .addFilterBefore(new AgentAuthenticationFilter(agentAuth), AnonymousAuthenticationFilter.class)
                .exceptionHandling(e -> e.authenticationEntryPoint(problems.agentEntryPoint())
                        .accessDeniedHandler(problems.accessDeniedHandler()));
        return http.build();
    }

    @Bean
    @Order(2)
    SecurityFilterChain userApi(HttpSecurity http, UserJwtAuthenticationConverter converter,
            ProblemResponses problems, ShscProperties properties) throws Exception {
        CookieCsrfTokenRepository csrfRepository = CookieCsrfTokenRepository.withHttpOnlyFalse();
        csrfRepository.setCookieCustomizer(cookie -> cookie
                .secure(properties.security().session().cookieSecure())
                .sameSite("Strict")
                .path("/"));
        CsrfTokenRequestAttributeHandler csrfHandler = new CsrfTokenRequestAttributeHandler();

        http.securityMatcher("/api/**")
                .csrf(csrf -> csrf.csrfTokenRepository(csrfRepository)
                        .csrfTokenRequestHandler(csrfHandler)
                        .requireCsrfProtectionMatcher(COOKIE_ENDPOINTS)
                        // Stateless API: by default every bearer-authenticated request would
                        // clear the XSRF-TOKEN cookie (CsrfAuthenticationStrategy), breaking the
                        // next refresh/logout. There is no server session to fixate here.
                        .sessionAuthenticationStrategy(new NullAuthenticatedSessionStrategy()))
                .cors(Customizer.withDefaults())
                .httpBasic(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable)
                .requestCache(AbstractHttpConfigurer::disable)
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .headers(SecurityConfig::headers)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.GET, "/api/v1/auth/csrf").permitAll()
                        .requestMatchers(HttpMethod.POST, PUBLIC_AUTH_POSTS).permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/v1/openapi.json", "/api/v1/openapi.json/**",
                                "/api/v1/docs", "/api/v1/docs/**").permitAll()
                        .anyRequest().authenticated())
                .oauth2ResourceServer(oauth -> oauth
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(converter))
                        .authenticationEntryPoint(problems.userEntryPoint()))
                .exceptionHandling(e -> e.authenticationEntryPoint(problems.userEntryPoint())
                        .accessDeniedHandler(problems.accessDeniedHandler()));
        return http.build();
    }

    @Bean
    @Order(3)
    SecurityFilterChain everythingElse(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable)
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .headers(SecurityConfig::headers)
                .authorizeHttpRequests(auth -> auth
                        // only "health" is exposed by actuator; other actuator paths answer 404
                        .requestMatchers("/actuator/**", "/error").permitAll()
                        .requestMatchers(HttpMethod.GET, "/swagger-ui/**").permitAll()
                        .anyRequest().denyAll());
        return http.build();
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource(ShscProperties properties) {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        List<String> origins = properties.security().cors().allowedOrigins();
        if (!origins.isEmpty()) {
            CorsConfiguration config = new CorsConfiguration();
            config.setAllowedOrigins(origins);
            config.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE"));
            config.setAllowedHeaders(List.of("Authorization", "Content-Type", "X-XSRF-TOKEN"));
            config.setAllowCredentials(true);
            config.setMaxAge(Duration.ofHours(1));
            source.registerCorsConfiguration("/api/**", config);
        }
        return source;
    }

    private static void headers(
            org.springframework.security.config.annotation.web.configurers.HeadersConfigurer<HttpSecurity> headers) {
        headers.httpStrictTransportSecurity(hsts -> hsts.disable())
                .frameOptions(frame -> frame.disable())
                .contentTypeOptions(cto -> cto.disable());
    }
}

package com.shsc.identity.access;

import java.util.Collection;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

/** Authentication of a user request: verified access token + principal loaded from the DB. */
public class UserAuthentication extends AbstractAuthenticationToken {

    private final AuthenticatedUser principal;
    private final transient Jwt token;

    public UserAuthentication(AuthenticatedUser principal, Jwt token,
            Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = principal;
        this.token = token;
        setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return token;
    }

    @Override
    public AuthenticatedUser getPrincipal() {
        return principal;
    }

    @Override
    public String getName() {
        return principal.userId().toString();
    }
}

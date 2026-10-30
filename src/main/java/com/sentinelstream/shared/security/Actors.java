package com.sentinelstream.shared.security;

import com.sentinelstream.shared.error.ApiException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Resolves the caller. The tenant comes from a {@code tenant} claim, or failing that from the part of
 * the subject after '@' (mock-oauth2 client ids look like {@code analyst@acme}). A token with neither
 * is refused rather than defaulted to some tenant.
 */
public final class Actors {

    private static final Pattern TENANT = Pattern.compile("[a-z0-9][a-z0-9-]{0,31}");

    private Actors() {
    }

    public static Actor current() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null) {
            throw new ApiException(401, "unauthenticated", "no caller");
        }
        if (auth.getPrincipal() instanceof Actor a) {
            return a;
        }
        if (auth instanceof JwtAuthenticationToken jwt) {
            return fromJwt(jwt.getToken(), auth.getAuthorities().stream().map(GrantedAuthority::getAuthority)
                    .filter(s -> s.startsWith("SCOPE_")).map(s -> s.substring(6)).collect(Collectors.toUnmodifiableSet()));
        }
        throw new ApiException(401, "unauthenticated", "unsupported credentials");
    }

    static Actor fromJwt(Jwt jwt, Set<String> scopes) {
        String sub = jwt.getSubject();
        String tenant = jwt.getClaimAsString("tenant");
        if (tenant == null && sub != null && sub.contains("@")) {
            tenant = sub.substring(sub.lastIndexOf('@') + 1);
        }
        if (tenant == null || !TENANT.matcher(tenant).matches()) {
            throw ApiException.forbidden("no-tenant", "token carries no usable tenant");
        }
        return new Actor(tenant, sub, scopes);
    }

    public static Actor require(String scope) {
        Actor a = current();
        if (!a.has(scope)) {
            throw ApiException.forbidden("forbidden", "requires scope " + scope);
        }
        return a;
    }
}

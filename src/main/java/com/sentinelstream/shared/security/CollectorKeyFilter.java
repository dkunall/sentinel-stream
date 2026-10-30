package com.sentinelstream.shared.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sentinelstream.shared.web.ProblemWriter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Set;

/** Authenticates {@code X-Api-Key} on the collector door. Keys are compared by hash, never stored in clear. */
@Component
public class CollectorKeyFilter extends OncePerRequestFilter {

    private final CollectorKeys keys;
    private final ObjectMapper json;

    CollectorKeyFilter(CollectorKeys keys, ObjectMapper json) {
        this.keys = keys;
        this.json = json;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {
        String key = req.getHeader("X-Api-Key");
        if (key == null || key.length() < 20 || key.length() > 200) {
            ProblemWriter.write(res, json, HttpStatus.UNAUTHORIZED, "unauthenticated", "A valid X-Api-Key is required");
            return;
        }
        var id = keys.byHash(sha256(key));
        if (id.isEmpty()) {
            ProblemWriter.write(res, json, HttpStatus.UNAUTHORIZED, "unauthenticated", "A valid X-Api-Key is required");
            return;
        }
        Actor actor = new Actor(id.get().tenant(), "collector:" + id.get().name(), Set.of(Actor.COLLECTOR));
        var auth = new AbstractAuthenticationToken(AuthorityUtils.createAuthorityList("SCOPE_" + Actor.COLLECTOR)) {
            @Override
            public Object getCredentials() {
                return "";
            }

            @Override
            public Object getPrincipal() {
                return actor;
            }
        };
        auth.setAuthenticated(true);
        var ctx = SecurityContextHolder.createEmptyContext();
        ctx.setAuthentication(auth);
        SecurityContextHolder.setContext(ctx);
        try {
            chain.doFilter(req, res);
        } finally {
            SecurityContextHolder.clearContext();
        }
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !("POST".equals(request.getMethod()) && "/v1/events:batch".equals(request.getRequestURI()));
    }

    public static String sha256(String s) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}

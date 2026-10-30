package com.sentinelstream.shared.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sentinelstream.shared.web.ProblemWriter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.boot.web.servlet.FilterRegistrationBean;

/**
 * Two doors. Collectors post events with an API key (they are machines; giving every log shipper an
 * OAuth client is more than most deployments run). Everything else is people or services with a JWT.
 * The demo webhook receiver authenticates the sender by HMAC instead, inside the controller.
 */
@Configuration(proxyBeanMethods = false)
class SecurityConfig {

    static final String ANALYST = "SCOPE_" + Actor.ANALYST;

    @Bean
    @Order(1)
    SecurityFilterChain collectors(HttpSecurity http, ObjectMapper json, CollectorKeyFilter keys) throws Exception {
        http.securityMatcher(req -> "POST".equals(req.getMethod()) && "/v1/events:batch".equals(req.getRequestURI()))
                .csrf(c -> c.disable())
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(keys, AnonymousAuthenticationFilter.class)
                .authorizeHttpRequests(a -> a.anyRequest().authenticated())
                .exceptionHandling(e -> e.authenticationEntryPoint((req, res, ex) -> ProblemWriter.write(res, json,
                        HttpStatus.UNAUTHORIZED, "unauthenticated", "A valid X-Api-Key is required")));
        return http.build();
    }

    @Bean
    @Order(2)
    SecurityFilterChain api(HttpSecurity http, ObjectMapper json) throws Exception {
        http.csrf(c -> c.disable())
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(a -> a
                        .requestMatchers("/actuator/health/**", "/actuator/prometheus").permitAll()
                        .requestMatchers("/demo/webhook-sink").permitAll()
                        .requestMatchers("/v1/audit/public-key").permitAll()
                        .requestMatchers("/v1/**").hasAuthority(ANALYST)
                        .anyRequest().denyAll())
                .oauth2ResourceServer(o -> o.jwt(j -> { })
                        .authenticationEntryPoint((req, res, ex) -> ProblemWriter.write(res, json,
                                HttpStatus.UNAUTHORIZED, "unauthenticated", "A valid bearer token is required"))
                        .accessDeniedHandler((req, res, ex) -> ProblemWriter.write(res, json,
                                HttpStatus.FORBIDDEN, "forbidden", "Token lacks the required scope")))
                .exceptionHandling(e -> e
                        .authenticationEntryPoint((req, res, ex) -> ProblemWriter.write(res, json,
                                HttpStatus.UNAUTHORIZED, "unauthenticated", "A valid bearer token is required"))
                        .accessDeniedHandler((req, res, ex) -> ProblemWriter.write(res, json,
                                HttpStatus.FORBIDDEN, "forbidden", "Token lacks the required scope")));
        return http.build();
    }

    /** The key filter belongs to the collector chain only, not to the plain servlet filter chain. */
    @Bean
    FilterRegistrationBean<CollectorKeyFilter> collectorKeyFilterRegistration(CollectorKeyFilter filter) {
        FilterRegistrationBean<CollectorKeyFilter> reg = new FilterRegistrationBean<>(filter);
        reg.setEnabled(false);
        return reg;
    }
}

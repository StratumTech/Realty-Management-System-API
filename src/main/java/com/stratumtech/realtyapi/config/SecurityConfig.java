package com.stratumtech.realtyapi.config;

import reactor.core.publisher.Mono;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpMethod;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;

import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2
        .server.resource.web.server.authentication.ServerBearerTokenAuthenticationConverter;

import org.springframework.security.web.server.SecurityWebFilterChain;

import org.springframework.core.convert.converter.Converter;

@Configuration
@EnableWebFluxSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final ReactiveJwtDecoder jwtDecoder;

    private final Converter<Jwt, Mono<AbstractAuthenticationToken>> jwtAuthConverter;

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(
            ServerHttpSecurity http,
            ServerBearerTokenAuthenticationConverter tokenConverter
    ) {

        http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers(HttpMethod.GET, "/api/v1/agents")
                        .hasAnyRole("ADMIN", "REGIONAL_ADMIN", "AGENT")

                        .pathMatchers(HttpMethod.GET, "/api/v1/agents/{agentUuid}")
                        .permitAll()

                        .pathMatchers(HttpMethod.PUT, "/api/v1/agents/{agentUuid}")
                        .hasRole("AGENT")

                        .pathMatchers(HttpMethod.PUT, "/api/v1/agents/{agentUuid}/block")
                        .hasAnyRole("ADMIN", "REGIONAL_ADMIN")
                        .pathMatchers(HttpMethod.PUT, "/api/v1/agents/{agentUuid}/unblock")
                        .hasAnyRole("ADMIN", "REGIONAL_ADMIN")

                        .pathMatchers(HttpMethod.GET, "/api/v1/agents/{agentUuid}/properties")
                        .permitAll()
                        .pathMatchers(HttpMethod.POST, "/api/v1/agents/{agentUuid}/properties")
                        .hasRole("AGENT")

                        .pathMatchers(HttpMethod.GET, "/api/v1/agents/{agentUuid}/properties/{propertyUuid}")
                        .permitAll()

                        .pathMatchers(HttpMethod.PUT, "/api/v1/agents/{agentUuid}/properties/{propertyUuid}")
                        .hasRole("AGENT")

                        .pathMatchers(HttpMethod.DELETE, "/api/v1/agents/{agentUuid}/properties/{propertyUuid}")
                        .hasRole("AGENT")

                        .pathMatchers(HttpMethod.GET, "/api/v1/agents/{agentUuid}/properties/{propertyUuid}/calendar")
                        .permitAll()

                        .pathMatchers(HttpMethod.PUT, "/api/v1/agents/{agentUuid}/properties/{propertyUuid}/calendar")
                        .hasRole("AGENT")

                        .pathMatchers(HttpMethod.GET, "/api/v1/agent-requests")
                        .hasRole("REGIONAL_ADMIN")
                        .pathMatchers(HttpMethod.PUT, "/api/v1/agent-requests/{id}/approve")
                        .hasRole("REGIONAL_ADMIN")
                        .pathMatchers(HttpMethod.PUT, "/api/v1/agent-requests/{id}/reject")
                        .hasRole("REGIONAL_ADMIN")

                        .pathMatchers(HttpMethod.GET, "/api/v1/admin-requests")
                        .hasRole("ADMIN")
                        .pathMatchers(HttpMethod.POST, "/api/v1/admin-requests/{id}/approve")
                        .hasRole("ADMIN")
                        .pathMatchers(HttpMethod.POST, "/api/v1/admin-requests/{id}/reject")
                        .hasRole("ADMIN")
                        .pathMatchers(HttpMethod.GET, "/api/v1/admins")
                        .hasRole("ADMIN")
                        .pathMatchers(HttpMethod.PUT, "/api/v1/admins/{adminUuid}/block")
                        .hasRole("ADMIN")
                        .pathMatchers(HttpMethod.PUT, "/api/v1/admins/{adminUuid}/unblock")
                        .hasRole("ADMIN")

                        .pathMatchers(HttpMethod.GET, "/api/v1/questions")
                        .hasAnyRole("ADMIN", "REGIONAL_ADMIN")
                        .pathMatchers(HttpMethod.POST, "/api/v1/questions")
                        .hasAnyRole("REGIONAL_ADMIN", "AGENT")
                        .pathMatchers(HttpMethod.POST, "/api/v1/questions/{id}")
                        .hasAnyRole("ADMIN", "REGIONAL_ADMIN")

                        .pathMatchers(
                                HttpMethod.POST,
                                "/api/v1/auth/login",
                                "/api/v1/auth/register"
                        )
                        .permitAll()

                        .pathMatchers(HttpMethod.GET, "/api/v1/regions")
                        .permitAll()

                        .anyExchange().permitAll()
                ).oauth2ResourceServer(oauth2 -> oauth2
                        .bearerTokenConverter(tokenConverter)
                        .jwt(jwt -> jwt.jwtDecoder(jwtDecoder))
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthConverter))
                );

        return http.build();
    }

}


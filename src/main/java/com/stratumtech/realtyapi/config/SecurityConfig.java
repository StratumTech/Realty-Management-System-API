package com.stratumtech.realtyapi.config;

import reactor.core.publisher.Mono;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;

import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;

import org.springframework.security.web.server.SecurityWebFilterChain;

import org.springframework.core.convert.converter.Converter;

import com.stratumtech.realtyapi.config.handler.CookieClearingServerLogoutHandler;
import com.stratumtech.realtyapi.config.converter.DefaultServerBearerTokenAuthenticationConverter;

@Configuration
@EnableWebFluxSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final ReactiveJwtDecoder jwtDecoder;

    private final Converter<Jwt, Mono<AbstractAuthenticationToken>> jwtAuthConverter;

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(
            ServerHttpSecurity http,
            DefaultServerBearerTokenAuthenticationConverter tokenConverter
    ) {

        http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers("/api/v1/auth/**").permitAll()
                        .anyExchange().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                        .bearerTokenConverter(tokenConverter)
                        .jwt(
                                jwt -> jwt
                                        .jwtDecoder(jwtDecoder)
                                        .jwtAuthenticationConverter(jwtAuthConverter)
                        )
                )
                .logout(logout -> logout
                        .logoutHandler(new CookieClearingServerLogoutHandler("__Host-auth-token"))
                );

        return http.build();
    }

}


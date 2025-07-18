package com.stratumtech.realtyapi.config.handler;

import java.time.Duration;

import reactor.core.publisher.Mono;

import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.logout.ServerLogoutHandler;

public class CookieClearingServerLogoutHandler implements ServerLogoutHandler {

    private final String cookieName;

    public CookieClearingServerLogoutHandler(String cookieName) {
        this.cookieName = cookieName;
    }

    @Override
    public Mono<Void> logout(WebFilterExchange exchange, Authentication authentication) {
        ResponseCookie cookie = ResponseCookie.from(cookieName, "")
                .path("/")
                .maxAge(Duration.ZERO)
                .httpOnly(true)
                .build();
        exchange.getExchange().getResponse().addCookie(cookie);
        return Mono.empty();
    }
}

package com.stratumtech.realtyapi.config.converter;

import reactor.core.publisher.Mono;
import org.springframework.http.HttpCookie;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2
        .server.resource.web.server.authentication.ServerBearerTokenAuthenticationConverter;

@Component
public class DefaultServerBearerTokenAuthenticationConverter
        extends ServerBearerTokenAuthenticationConverter {
    @Override
    public Mono<Authentication> convert(ServerWebExchange exchange) {
        HttpCookie cookie = exchange.getRequest()
                .getCookies()
                .getFirst("SESSION_JWT");
        if (cookie == null || cookie.getValue().isBlank()) {
            return Mono.empty();
        }
        return Mono.just(new BearerTokenAuthenticationToken(cookie.getValue()));
    }
}

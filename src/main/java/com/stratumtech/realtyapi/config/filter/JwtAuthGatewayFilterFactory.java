package com.stratumtech.realtyapi.config.filter;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.stereotype.Component;

import java.util.List;

@Component("JwtAuth")
public class JwtAuthGatewayFilterFactory
        extends AbstractGatewayFilterFactory<Object> {

    private final ReactiveJwtDecoder jwtDecoder;

    public JwtAuthGatewayFilterFactory(ReactiveJwtDecoder jwtDecoder) {
        this.jwtDecoder = jwtDecoder;
    }

    @Override
    public GatewayFilter apply(Object config) {
        return (exchange, chain) -> {
            var cookie = exchange.getRequest()
                    .getCookies()
                    .getFirst("SESSION_JWT");

            String token = cookie.getValue();
            return jwtDecoder
                    .decode(token)
                    .flatMap(jwt -> {
                        String userId = jwt.getSubject();
                        List<String> roles = jwt.getClaimAsStringList("roles");

                        var mutatedReq = exchange.getRequest().mutate()
                                .header("X-User-ID", userId)
                                .header("X-User-Roles", String.join(",", roles))
                                .build();

                        return chain.filter(exchange.mutate().request(mutatedReq).build());
                    })
                    .onErrorResume(e -> {
                        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                        return exchange.getResponse().setComplete();
                    });
        };
    }
}

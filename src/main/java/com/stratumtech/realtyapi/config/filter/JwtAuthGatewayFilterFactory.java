package com.stratumtech.realtyapi.config.filter;

import lombok.extern.slf4j.Slf4j;
import lombok.RequiredArgsConstructor;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;

@Slf4j
@Component("JwtAuth")
@RequiredArgsConstructor
public class JwtAuthGatewayFilterFactory
        extends AbstractGatewayFilterFactory<Object> {

    private final ReactiveJwtDecoder jwtDecoder;

    @Override
    public GatewayFilter apply(Object config) {
        return (exchange, chain) -> {
            log.debug("Start to authenticate");
            var cookie = exchange.getRequest()
                    .getCookies()
                    .getFirst("__Host-auth-token");

            log.debug("Cookie: {}", cookie);

            String token = cookie.getValue();
            return jwtDecoder
                    .decode(token)
                    .flatMap(jwt -> {
                        String userId = jwt.getClaimAsString("jti");
                        String role = jwt.getClaimAsString("role");
                        log.debug("User id from cookie: {}", userId);
                        log.debug("User role from cookie: {}", role);
                        var mutatedReq = exchange.getRequest().mutate()
                                .header("X-USER-UUID", userId)
                                .header("X-USER-ROLE", role);

                        if(role.endsWith("REGIONAL_AGENT")){
                            String regionId = jwt.getClaimAsString("adminRegionId");
                            String referralCode = jwt.getClaimAsString("adminReferralCode");
                            mutatedReq.header("X-ADMIN-REGION-ID", regionId);
                            mutatedReq.header("X-ADMIN-REFERRAL-CODE", referralCode);
                        }

                        return chain.filter(exchange.mutate().request(mutatedReq.build()).build());
                    })
                    .onErrorResume(e -> {
                        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                        return exchange.getResponse().setComplete();
                    });
        };
    }
}

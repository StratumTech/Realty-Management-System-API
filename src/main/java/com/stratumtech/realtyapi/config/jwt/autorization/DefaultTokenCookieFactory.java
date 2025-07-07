package com.stratumtech.realtyapi.config.jwt.autorization;

import java.util.Map;
import java.util.UUID;
import java.time.Instant;
import java.time.Duration;
import java.util.function.Function;

import lombok.Setter;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

@Setter
public class DefaultTokenCookieFactory implements Function<Authentication, Token> {

    private Duration tokenTTL = Duration.ofDays(1);

    @Override
    public Token apply(Authentication authentication) {
        Map<?, ?> details = (Map<?, ?>) authentication.getDetails();
        var now = Instant.now();
        return new Token(UUID.randomUUID(), authentication.getName(),
                         authentication.getAuthorities().stream()
                                 .map(GrantedAuthority::getAuthority).toList(),
                         (String) details.get("role"),
                         (int) details.get("region"),
                         now, now.plus(this.tokenTTL));
    }
}

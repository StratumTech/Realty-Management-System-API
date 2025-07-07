package com.stratumtech.realtyapi.config.jwt.autorization.strategy;

import java.time.Instant;
import java.util.Objects;
import java.util.function.Function;
import java.time.temporal.ChronoUnit;

import com.stratumtech.realtyapi.config.jwt.autorization.Token;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import lombok.Setter;

import org.springframework.security.core.Authentication;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;

@Setter
public class TokenCookieSessionAuthenticationStrategy implements SessionAuthenticationStrategy {

    private Function<Authentication, Token> tokenCookieFactory;

    private Function<Token, String> tokenStringSerializer = Objects::toString;

    @Override
    public void onAuthentication(Authentication authentication,
                                 HttpServletRequest request,
                                 HttpServletResponse response) throws SessionAuthenticationException {
        if(authentication instanceof UsernamePasswordAuthenticationToken){
            var token = tokenCookieFactory.apply(authentication);
            var tokenString = this.tokenStringSerializer.apply(token);

            var cookie = new Cookie("__Host-auth-token", tokenString);
            cookie.setPath("/");
            cookie.setDomain(null);
            cookie.setSecure(true);
            cookie.setHttpOnly(true);
            cookie.setMaxAge((int) ChronoUnit.SECONDS.between(Instant.now(), token.expiresAt()));

            response.addCookie(cookie);
        }
    }
}

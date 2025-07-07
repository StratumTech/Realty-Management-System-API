package com.stratumtech.realtyapi.config.jwt.autorization.configurer;

import java.util.function.Function;

import jakarta.servlet.http.HttpServletResponse;

import org.springframework.stereotype.Service;

import org.springframework.security.web.csrf.CsrfFilter;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

import org.springframework.security.authentication.AuthenticationManager;

import org.springframework.security.web.authentication.AuthenticationFilter;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.security.web.authentication.logout.CookieClearingLogoutHandler;
import org.springframework.security.web.authentication.AuthenticationEntryPointFailureHandler;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;

import com.stratumtech.realtyapi.config.jwt.autorization.Token;
import com.stratumtech.realtyapi.service.RemoteUserDetailsService;
import com.stratumtech.realtyapi.config.jwt.autorization.TokenUser;
import com.stratumtech.realtyapi.config.jwt.autorization.TokenCookieAuthenticationConverter;


@Service
public class TokenCookieAuthenticationConfigurer
        extends AbstractHttpConfigurer<TokenCookieAuthenticationConfigurer, HttpSecurity> {

    private Function<String, Token> tokenCookieStringDeserializer;

    @Override
    public void init(HttpSecurity builder) throws Exception {
        builder.logout(logout -> logout
                .addLogoutHandler(new CookieClearingLogoutHandler("__Host-auth-token"))
                .addLogoutHandler((request, response, authentication) -> {
                    if(authentication != null && authentication.getPrincipal() instanceof TokenUser user){
                        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
                    }
                })
        );
    }

    @Override
    public void configure(HttpSecurity builder) {
        var cookieAuthenticationFilter = new AuthenticationFilter(
                builder.getSharedObject(AuthenticationManager.class),
                new TokenCookieAuthenticationConverter(this.tokenCookieStringDeserializer)
        );
        cookieAuthenticationFilter.setSuccessHandler((request, response, authentication) -> {});
        cookieAuthenticationFilter.setFailureHandler(
                new AuthenticationEntryPointFailureHandler(
                        new Http403ForbiddenEntryPoint()
                )
        );

        var authenticationPrivider = new PreAuthenticatedAuthenticationProvider();
        authenticationPrivider.setPreAuthenticatedUserDetailsService(
                new RemoteUserDetailsService()
        );

        builder.addFilterAfter(cookieAuthenticationFilter, CsrfFilter.class)
                .authenticationProvider(authenticationPrivider);
    }

    public TokenCookieAuthenticationConfigurer setTokenCookieStringDeserializer(
            Function<String, Token> tokenCookieStringDeserializer) {
        this.tokenCookieStringDeserializer = tokenCookieStringDeserializer;
        return this;
    }
}

package com.stratumtech.realtyapi.config;

import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.jwk.OctetSequenceKey;

import lombok.RequiredArgsConstructor;

import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;

import org.springframework.beans.factory.annotation.Value;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;

import static org.springframework.security.config.Customizer.withDefaults;

import com.stratumtech.realtyapi.config.jwt.autorization.filter.FindCsrfTokenFilter;
import com.stratumtech.realtyapi.config.jwt.autorization.TokenCookieJweStringSerializer;
import com.stratumtech.realtyapi.config.jwt.autorization.configurer.TokenCookieAuthenticationConfigurer;
import com.stratumtech.realtyapi.config.jwt.autorization.strategy.TokenCookieSessionAuthenticationStrategy;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    @Bean
    public TokenCookieJweStringSerializer tokenCookieJweStringSerializer(
            @Value("${jwt.cookie-token-key}") String cookieTokenKey
    ) throws Exception {
        return new TokenCookieJweStringSerializer(new DirectEncrypter(
                OctetSequenceKey.parse(cookieTokenKey)
        ));
    }

    @Bean
    public SecurityFilterChain filterChain(
            HttpSecurity http,
            TokenCookieAuthenticationConfigurer configurer,
            TokenCookieJweStringSerializer serializer) throws Exception {
        final String[] ADMINISTRATORS = { "ADMIN", "REGIONAL_ADMIN" };
        final String[] ALL_SYSTEMS_ROLES = { "ADMIN", "REGIONAL_ADMIN", "AGENT" };

        var tokenCookieSessionAuthenticationStrategy = new TokenCookieSessionAuthenticationStrategy();
        tokenCookieSessionAuthenticationStrategy.setTokenStringSerializer(serializer);

        http.httpBasic(withDefaults())
                .addFilterAfter(new FindCsrfTokenFilter(), ExceptionTranslationFilter.class)
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()

                ).sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                        .sessionAuthenticationStrategy(tokenCookieSessionAuthenticationStrategy)
                ).exceptionHandling(exception -> exception
                        .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
                ).cors(withDefaults())
                .csrf(csrf -> csrf
                        .csrfTokenRepository(new CookieCsrfTokenRepository())
                        .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler())
                        .sessionAuthenticationStrategy(((authentication, request, response) -> {}))
                );

        return http.build();
    }
}

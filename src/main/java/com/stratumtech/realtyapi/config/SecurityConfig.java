package com.stratumtech.realtyapi.config;

import lombok.RequiredArgsConstructor;

import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static org.springframework.security.config.Customizer.withDefaults;

import com.stratumtech.realtyapi.config.filter.JwtRequestFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtRequestFilter jwtRequestFilter;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        final String[] ADMINISTRATORS = { "ADMIN", "REGIONAL_ADMIN" };
        final String[] ALL_SYSTEMS_ROLES = { "ADMIN", "REGIONAL_ADMIN", "AGENT" };

        http
                .cors(withDefaults())
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()

                        .requestMatchers("**/properties").hasAnyRole(ADMINISTRATORS)
                        .requestMatchers("**/properties/**").hasAnyRole(ADMINISTRATORS)

                        .requestMatchers(HttpMethod.GET, "**/users").hasAnyRole(ADMINISTRATORS)
                        .requestMatchers(HttpMethod.GET, "**/users/**").permitAll()

                        .requestMatchers(HttpMethod.PUT, "**/users/**").hasAnyRole(ALL_SYSTEMS_ROLES)
                        .requestMatchers(HttpMethod.DELETE, "**/users/**").hasAnyRole(ALL_SYSTEMS_ROLES)

                        .requestMatchers(HttpMethod.GET, "**/users/**/stats").hasAnyRole(ALL_SYSTEMS_ROLES)
                        .requestMatchers(HttpMethod.GET, "**/users/**/export").hasAnyRole(ALL_SYSTEMS_ROLES)
                        .requestMatchers(HttpMethod.PUT, "**/users/**/block").hasAnyRole(ADMINISTRATORS)

                        .requestMatchers(HttpMethod.GET, "**/users/**/properties").permitAll()
                        .requestMatchers(HttpMethod.POST, "**/users/**/properties").hasAnyRole(ALL_SYSTEMS_ROLES)

                        .requestMatchers(HttpMethod.GET, "**/users/**/properties/**").permitAll()
                        .requestMatchers(HttpMethod.PUT, "**/users/**/properties/**").hasAnyRole(ALL_SYSTEMS_ROLES)
                        .requestMatchers(HttpMethod.DELETE, "**/users/**/properties/**").hasAnyRole(ALL_SYSTEMS_ROLES)

                        .requestMatchers(HttpMethod.POST, "**/auth/register").permitAll()
                        .requestMatchers(HttpMethod.POST, "**/auth/login").permitAll()
                        .requestMatchers(HttpMethod.GET, "**/auth/token").hasAnyRole(ALL_SYSTEMS_ROLES)
                ).sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                ).exceptionHandling(exception -> exception
                        .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
                ).addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

}

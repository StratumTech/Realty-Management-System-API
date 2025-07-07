package com.stratumtech.realtyapi.service;

import java.util.Map;
import java.util.Collection;

import lombok.RequiredArgsConstructor;

import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Value;

import org.springframework.security.core.userdetails.*;
import org.springframework.security.core.GrantedAuthority;

import org.springframework.web.client.RestTemplate;

import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

import com.stratumtech.realtyapi.dto.UserDto;

@Service
@RequiredArgsConstructor
public class RemoteUserDetailsService
        implements UserDetailsService, AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> {

    private static final String USER_URL = "lb://%s/api/v1/users/%s";

    private Map<String, Collection<? extends GrantedAuthority>> authoritiesByRole;

    @Value("${user.service.name}")
    private String userServiceName;

    private RestTemplate restTemplate;

    @Override
    public UserDetails loadUserDetails(PreAuthenticatedAuthenticationToken token) throws UsernameNotFoundException {
        return loadUserDetails((String) token.getPrincipal());
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return loadUserDetails(username);
    }

    private UserDetails loadUserDetails(String uuid) throws UsernameNotFoundException {
        final UserDto user = restTemplate.getForObject(
                String.format(USER_URL, userServiceName, uuid),
                UserDto.class
        );

        return User.builder()
                .username(user.getUuid().toString())
                .password(user.getPassword())
                .roles(user.getRole())
                .authorities(authoritiesByRole.get(user.getRole()))
                .build();
    }
}

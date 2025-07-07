package com.stratumtech.realtyapi.config;

import java.util.Map;
import java.util.HashMap;
import java.util.Collection;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.Configuration;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

@Configuration
public class AuthorityConfig {

    @Bean
    @Scope("singleton")
    public Map<String, Collection<? extends GrantedAuthority>> findAuthoritiesByRole() {
        Map<String, Collection<? extends GrantedAuthority>> map = new HashMap<>();

        map.put(
                "ROLE_AGENT",
                AuthorityUtils.createAuthorityList("PRIVILEGE_READ")
        );

        map.put(
                "ROLE_ADMIN",
                AuthorityUtils.createAuthorityList("PRIVILEGE_READ",
                                                   "PRIVILEGE_WRITE",
                                                   "PRIVILEGE_DELETE",
                                                   "PRIVILEGE_UPDATE")
        );

        map.put(
                "ROLE_REGIONAL_ADMIN",
                AuthorityUtils.createAuthorityList("PRIVILEGE_READ",
                                                   "PRIVILEGE_WRITE",
                                                   "PRIVILEGE_DELETE",
                                                   "PRIVILEGE_UPDATE")
        );

        return map;
    }

}


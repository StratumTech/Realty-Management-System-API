package com.stratumtech.realtyapi.config;

import org.springframework.web.client.RestTemplate;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.cloud.client.loadbalancer.LoadBalanced;

@Configuration
public class ClientConfig {

    @Bean
    @LoadBalanced
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
}
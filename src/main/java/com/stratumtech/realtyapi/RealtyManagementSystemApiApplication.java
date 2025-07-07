package com.stratumtech.realtyapi;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

@SpringBootApplication
@EnableDiscoveryClient
public class RealtyManagementSystemApiApplication {

    public static void main(String[] args) {
        SpringApplication.run(RealtyManagementSystemApiApplication.class, args);
    }

}

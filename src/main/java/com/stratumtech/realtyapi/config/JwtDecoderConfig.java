package com.stratumtech.realtyapi.config;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWEDecryptionKeySelector;
import com.nimbusds.jose.proc.JWEKeySelector;
import com.nimbusds.jose.proc.SecurityContext;

import org.springframework.context.annotation.Bean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.text.ParseException;

@Configuration
public class JwtDecoderConfig {

    @Bean
    public ReactiveJwtDecoder reactiveJwtDecoder(
            @Value("${jwt.secret.key}") String cookieTokenKey
    ) throws ParseException {
        OctetSequenceKey jwk = OctetSequenceKey.parse(cookieTokenKey);

        SecretKey jwsKey = new SecretKeySpec(jwk.toByteArray(), "HmacSHA256");

        SecretKey jweKey = jwk.toSecretKey("AES");
        JWKSource<SecurityContext> jweSource = new ImmutableSecret<>(jweKey);

        JWEKeySelector<SecurityContext> jweSelector =
                new JWEDecryptionKeySelector<>(
                        JWEAlgorithm.DIR,
                        EncryptionMethod.A128GCM,
                        jweSource
                );

        return NimbusReactiveJwtDecoder
                .withSecretKey(jwsKey)
                .macAlgorithm(MacAlgorithm.HS256)
                .jwtProcessorCustomizer(processor ->
                        processor.setJWEKeySelector(jweSelector)
                )
                .build();
    }
}

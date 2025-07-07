package com.stratumtech.realtyapi.config.jwt.autorization;

import java.util.Date;
import java.util.function.Function;

import com.nimbusds.jose.*;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;

import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class TokenCookieJweStringSerializer implements Function<Token, String> {

    private final JWEEncrypter jweEncrypter;

    @Setter
    private JWEAlgorithm jweAlgorithm = JWEAlgorithm.DIR;

    @Setter
    private EncryptionMethod encryptionMethod = EncryptionMethod.A128GCM;

    public TokenCookieJweStringSerializer(JWEEncrypter jweEncrypter) {
        this.jweEncrypter = jweEncrypter;
    }

    public TokenCookieJweStringSerializer(JWEEncrypter jweEncrypter,
                                          JWEAlgorithm jweAlgorithm,
                                          EncryptionMethod encryptionMethod) {
        this.jweEncrypter = jweEncrypter;
        this.jweAlgorithm = jweAlgorithm;
        this.encryptionMethod = encryptionMethod;
    }

    @Override
    public String apply(Token token) {
        var jwsHeader = new JWEHeader.Builder(this.jweAlgorithm, this.encryptionMethod)
                .keyID(token.id().toString())
                .build();
        var claimsSet = new JWTClaimsSet.Builder()
                .jwtID(token.id().toString())
                .subject(token.subject())
                .issueTime(Date.from(token.createdAt()))
                .expirationTime(Date.from(token.expiresAt()))
                .claim("authorities", token.authorities())
                .claim("role", token.role())
                .claim("region", token.region())
                .build();
        var encryptedJWT = new EncryptedJWT(jwsHeader, claimsSet);
        try {
            encryptedJWT.encrypt(this.jweEncrypter);

            return encryptedJWT.serialize();
        } catch (JOSEException exception) {
            log.error(exception.getMessage(), exception);
        }

        return null;
    }

}
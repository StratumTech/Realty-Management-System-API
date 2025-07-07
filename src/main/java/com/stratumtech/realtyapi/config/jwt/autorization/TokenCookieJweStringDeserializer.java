package com.stratumtech.realtyapi.config.jwt.autorization;

import java.util.UUID;
import java.text.ParseException;
import java.util.function.Function;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jwt.EncryptedJWT;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class TokenCookieJweStringDeserializer implements Function<String, Token> {

    private final JWEDecrypter jweDecrypter;

    public TokenCookieJweStringDeserializer(JWEDecrypter jweDecrypter) {
        this.jweDecrypter = jweDecrypter;
    }

    @Override
    public Token apply(String string) {
        try {
            var encryptedJWT = EncryptedJWT.parse(string);
            encryptedJWT.decrypt(this.jweDecrypter);
            var claimsSet = encryptedJWT.getJWTClaimsSet();
            return new Token(UUID.fromString(claimsSet.getJWTID()), claimsSet.getSubject(),
                    claimsSet.getStringListClaim("authorities"),
                    claimsSet.getClaimAsString("role"),
                    claimsSet.getIntegerClaim("region"),
                    claimsSet.getIssueTime().toInstant(),
                    claimsSet.getExpirationTime().toInstant());
        } catch (ParseException | JOSEException exception) {
            log.error(exception.getMessage(), exception);
        }

        return null;
    }
}

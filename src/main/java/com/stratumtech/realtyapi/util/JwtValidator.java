package com.stratumtech.realtyapi.util;

import java.util.List;
import java.util.ArrayList;
import javax.crypto.SecretKey;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Value;

@Service
public final class JwtValidator {

    @Value("${jwt.secret}")
    private String secret;

    public String getUsername(String token) {
        final JwtParser jwtParser = Jwts.parser()
                .verifyWith(getSecretKey(secret))
                .build();
        return jwtParser.parseSignedClaims(token).getPayload().getSubject();
    }

    public List<String> getRoles(String token) {
        final JwtParser jwtParser = Jwts.parser()
                .verifyWith(getSecretKey(secret))
                .build();

        Claims claims = jwtParser.parseSignedClaims(token).getPayload();

        final List<String> roles = new ArrayList<>();

        ArrayList<?> rawList = claims.get("roles", ArrayList.class);
        rawList.forEach(r -> roles.add(r.toString()));

        return roles;
    }

    public void validateToken(String token){
        final JwtParser jwtParser = Jwts.parser()
                .verifyWith(getSecretKey(secret))
                .build();
        jwtParser.parse(token);
    }

    private SecretKey getSecretKey(String secret){
        byte[] keyBytes = Decoders.BASE64.decode(secret);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}

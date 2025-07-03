package com.stratumtech.realtyapi.config.filter;

import java.util.Map;
import java.util.stream.Collectors;

import java.io.IOException;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.core.JsonProcessingException;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.security.SignatureException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import lombok.extern.slf4j.Slf4j;
import lombok.RequiredArgsConstructor;

import com.stratumtech.realtyapi.util.JwtValidator;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtRequestFilter extends OncePerRequestFilter {

    private final JwtValidator validator;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        final String offset = "Bearer";
        final String authHeader = request.getHeader("Authorization");

        if(authHeader != null && authHeader.startsWith(offset)){
            String token = authHeader.substring(offset.length()+1);

            try{
                validator.validateToken(token);

                String username = validator.getUsername(token);

                if(!username.isBlank() && SecurityContextHolder.getContext().getAuthentication() == null){
                    var upaToken = new UsernamePasswordAuthenticationToken(
                            username,
                            null,
                            validator.getRoles(token).stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList())
                    );
                    SecurityContextHolder.getContext().setAuthentication(upaToken);
                }
            }catch(ExpiredJwtException e){
                log.info("Jwt \"time to live\" has expired");
                var message = Map.of(
                        "timestamp", LocalDateTime.now().truncatedTo(ChronoUnit.SECONDS),
                        "status", HttpStatus.UNAUTHORIZED.value(),
                        "error", "Jwt \"time to live\" has expired",
                        "message", e.getMessage());
                response.getWriter().write(convertObjectToJson(message));
            }catch(SignatureException e){
                log.info("Invalid jwt signature");
                var message = Map.of(
                        "timestamp", LocalDateTime.now().truncatedTo(ChronoUnit.SECONDS),
                        "status", HttpStatus.UNAUTHORIZED.value(),
                        "error", "Invalid jwt signature",
                        "message", e.getMessage());
                response.getWriter().write(convertObjectToJson(message));
            }
        }

        filterChain.doFilter(request, response);
    }

    public String convertObjectToJson(Object obj) {
        ObjectMapper objectMapper = new ObjectMapper();
        try {
            return objectMapper.writeValueAsString(obj);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }
}

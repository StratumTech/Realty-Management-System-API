package com.stratumtech.realtyapi.config.jwt.autorization.filter;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import lombok.Setter;

import org.springframework.http.MediaType;
import org.springframework.http.HttpMethod;

import com.fasterxml.jackson.databind.ObjectMapper;

import org.springframework.web.filter.OncePerRequestFilter;

import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;

@Setter
public class FindCsrfTokenFilter extends OncePerRequestFilter {

    private RequestMatcher requestMatcher = PathPatternRequestMatcher
                                            .withDefaults()
                                            .matcher(HttpMethod.GET, "/csrf");

    private CsrfTokenRepository csrfTokenRepository = new CookieCsrfTokenRepository();

    private ObjectMapper objectMapper = new ObjectMapper();

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        if (this.requestMatcher.matches(request)) {
            response.setStatus(HttpServletResponse.SC_OK);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            this.objectMapper.writeValue(
                    response.getWriter(),
                    this.csrfTokenRepository.loadDeferredToken(request, response).get()
            );
            return;
        }

        filterChain.doFilter(request, response);
    }
}

package com.stratumtech.realtyapi.config.jwt.autorization;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public record Token(UUID id, String subject, List<String> authorities, String role, int region, Instant createdAt,
                    Instant expiresAt) {
}
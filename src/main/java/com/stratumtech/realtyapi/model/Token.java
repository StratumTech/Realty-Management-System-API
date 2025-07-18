package com.stratumtech.realtyapi.model;

import java.util.UUID;
import java.time.Instant;

public record Token(
        UUID id,
        String role,
        Instant createdAt,
        Instant expiresAt
) {
}
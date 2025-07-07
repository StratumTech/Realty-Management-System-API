package com.stratumtech.realtyapi.dto;

import java.util.UUID;

import lombok.Data;
import lombok.Builder;

import jakarta.validation.constraints.NotNull;

@Data
@Builder
public final class UserDto {

    @NotNull
    private final UUID uuid;

    @NotNull
    private final String role;

    @NotNull
    private final Long regionId;

    @NotNull
    private final String password;

    @NotNull
    private final Boolean isBlocked;
}

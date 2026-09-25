package com.microchip.lambda_auth.domain.dto;

import com.microchip.lambda_auth.domain.User;
import java.time.Instant;
import java.util.UUID;

public record UserView(UUID id, String username, String role, boolean enabled, Instant createdAt) {

    public static UserView of(User user) {
        return new UserView(user.getId(), user.getUsername(), user.getRole().name(), user.isEnabled(), user.getCreatedAt());
    }
}

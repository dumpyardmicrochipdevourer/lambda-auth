package com.microchip.pathos_auth.domain.dto;

import com.microchip.pathos_auth.domain.User;
import java.time.Instant;
import java.util.Set;
import java.util.UUID;

public record UserView(UUID id, String username, String role, boolean enabled, Instant createdAt, Set<String> access) {

    public static UserView of(User user) {
        return new UserView(user.getId(), user.getUsername(), user.getRole().name(), user.isEnabled(),
                user.getCreatedAt(), user.getAccess());
    }
}

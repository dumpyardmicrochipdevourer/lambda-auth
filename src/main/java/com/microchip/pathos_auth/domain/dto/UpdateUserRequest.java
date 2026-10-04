package com.microchip.pathos_auth.domain.dto;

import java.util.Set;

public record UpdateUserRequest(Boolean enabled, Set<String> access) {
}

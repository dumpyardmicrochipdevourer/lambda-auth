package com.microchip.pathos_auth.domain.dto;

import java.time.Instant;

public record InviteView(String code, Instant createdAt, Instant expiresAt, String usedBy, Instant usedAt) {
}

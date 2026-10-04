package com.microchip.pathos_auth.domain.dto;

public record ChangePasswordRequest(String currentPassword, String newPassword) {
}

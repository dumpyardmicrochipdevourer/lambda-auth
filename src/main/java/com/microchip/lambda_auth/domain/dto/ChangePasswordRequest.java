package com.microchip.lambda_auth.domain.dto;

public record ChangePasswordRequest(String currentPassword, String newPassword) {
}

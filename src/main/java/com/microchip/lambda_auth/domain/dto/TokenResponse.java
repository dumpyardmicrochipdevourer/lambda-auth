package com.microchip.lambda_auth.domain.dto;

public record TokenResponse(String accessToken, String refreshToken, long expiresIn) {
    
}

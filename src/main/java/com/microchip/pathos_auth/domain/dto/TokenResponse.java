package com.microchip.pathos_auth.domain.dto;

public record TokenResponse(String accessToken, String refreshToken, long expiresIn) {
    
}

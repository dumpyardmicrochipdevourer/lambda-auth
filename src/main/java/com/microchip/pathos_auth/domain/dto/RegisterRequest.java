package com.microchip.pathos_auth.domain.dto;

public record RegisterRequest(String inviteCode, String username, String password) {
}

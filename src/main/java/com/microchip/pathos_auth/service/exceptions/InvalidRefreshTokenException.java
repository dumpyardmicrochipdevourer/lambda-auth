package com.microchip.pathos_auth.service.exceptions;

public class InvalidRefreshTokenException extends RuntimeException {

    public InvalidRefreshTokenException() {
        super("refresh-токен недействителен");
    }
}

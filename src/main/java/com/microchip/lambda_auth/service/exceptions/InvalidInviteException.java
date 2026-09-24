package com.microchip.lambda_auth.service.exceptions;

public class InvalidInviteException extends RuntimeException {

    public InvalidInviteException() {
        super("инвайт недействителен");
    }
}

package com.microchip.pathos_auth.service.exceptions;

public class InvalidInviteException extends RuntimeException {

    public InvalidInviteException() {
        super("инвайт недействителен");
    }
}

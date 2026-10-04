package com.microchip.pathos_auth.service.exceptions;

public class InvalidCredentialsException extends RuntimeException {

    public InvalidCredentialsException() {
        super("неверный логин или пароль");
    }
}

package com.microchip.lambda_auth.service.exceptions;

public class UsernameTakenException extends RuntimeException {

    public UsernameTakenException(String username) {
        super("имя занято: " + username);
    }
}

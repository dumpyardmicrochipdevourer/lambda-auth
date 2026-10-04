package com.microchip.pathos_auth.service.exceptions;

public class UsernameTakenException extends RuntimeException {

    public UsernameTakenException(String username) {
        super("имя занято: " + username);
    }
}

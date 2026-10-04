package com.microchip.pathos_auth.service.exceptions;

import java.util.UUID;

public class UserNotFoundException extends RuntimeException {

    public UserNotFoundException(UUID id) {
        super("пользователь не найден: " + id);
    }
}

package com.microchip.lambda_auth.service.util;

import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;
import org.springframework.stereotype.Component;

@Component
public class CredentialsValidator {

    private static final Pattern USERNAME = Pattern.compile("^[a-zA-Z0-9_]{3,32}$");
    private static final int PASSWORD_MIN_CHARS = 8;
    private static final int PASSWORD_MAX_BYTES = 72;

    public void validate(String username, String password) {
        if (username == null || !USERNAME.matcher(username).matches()) {
            throw new IllegalArgumentException("username: 3-32 символа, латиница, цифры и _");
        }
        if (password == null
                || password.length() < PASSWORD_MIN_CHARS
                || password.getBytes(StandardCharsets.UTF_8).length > PASSWORD_MAX_BYTES) {
            throw new IllegalArgumentException(
                    "password: от %d символов, не длиннее %d байт".formatted(PASSWORD_MIN_CHARS, PASSWORD_MAX_BYTES));
        }
    }
}

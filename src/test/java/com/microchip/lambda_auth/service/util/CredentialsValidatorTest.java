package com.microchip.lambda_auth.service.util;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class CredentialsValidatorTest {

    private final CredentialsValidator validator = new CredentialsValidator();

    @Test
    void acceptsValidCredentials() {
        assertDoesNotThrow(() -> validator.validate("kolya_01", "12345678"));
        assertDoesNotThrow(() -> validator.validate("a".repeat(32), "p".repeat(72)));
    }

    @Test
    void rejectsBadUsername() {
        for (String username : new String[] {null, "", "ab", "a".repeat(33), "kol ya", "коля", "kolya!"}) {
            assertThrows(IllegalArgumentException.class, () -> validator.validate(username, "12345678"));
        }
    }

    @Test
    void rejectsBadPassword() {
        for (String password : new String[] {null, "", "1234567", "p".repeat(73), "я".repeat(37)}) {
            assertThrows(IllegalArgumentException.class, () -> validator.validate("kolya", password));
        }
    }
}

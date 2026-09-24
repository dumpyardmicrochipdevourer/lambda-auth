package com.microchip.lambda_auth.service;

import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.microchip.lambda_auth.IntegrationTest;
import com.microchip.lambda_auth.domain.Role;
import com.microchip.lambda_auth.domain.User;
import com.microchip.lambda_auth.domain.dto.TokenResponse;
import com.microchip.lambda_auth.domain.repo.RefreshTokenRepository;
import com.microchip.lambda_auth.domain.repo.UserRepository;
import com.microchip.lambda_auth.service.exceptions.InvalidCredentialsException;
import com.microchip.lambda_auth.service.exceptions.InvalidRefreshTokenException;
import com.microchip.lambda_auth.service.util.RefreshTokenGenerator;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;

class AuthServiceTest extends IntegrationTest {

    private static final String PASSWORD = "secret";

    @Autowired AuthService authService;
    @Autowired UserRepository users;
    @Autowired RefreshTokenRepository tokens;
    @Autowired RefreshTokenGenerator generator;
    @Autowired PasswordEncoder encoder;

    @Test
    void loginStoresOnlyHashOfRefreshToken() {
        User user = user();

        TokenResponse response = authService.login(user.getUsername(), PASSWORD);

        assertTrue(tokens.findByTokenHash(generator.hash(response.refreshToken())).isPresent());
        assertTrue(tokens.findByTokenHash(response.refreshToken()).isEmpty());
    }

    @Test
    void loginIsCaseInsensitiveOnUsername() {
        User user = user();

        authService.login(user.getUsername().toUpperCase(), PASSWORD);
    }

    @Test
    void wrongPasswordUnknownUserAndDisabledUserAreIndistinguishable() {
        User user = user();
        User disabled = user();
        disabled.setEnabled(false);
        users.save(disabled);

        assertThrows(InvalidCredentialsException.class, () -> authService.login(user.getUsername(), "wrong"));
        assertThrows(InvalidCredentialsException.class, () -> authService.login("nobody-" + UUID.randomUUID(), PASSWORD));
        assertThrows(InvalidCredentialsException.class, () -> authService.login(disabled.getUsername(), PASSWORD));
    }

    @Test
    void refreshRotatesToken() {
        User user = user();
        TokenResponse first = authService.login(user.getUsername(), PASSWORD);

        TokenResponse second = authService.refresh(first.refreshToken());

        assertNotEquals(first.refreshToken(), second.refreshToken());
        authService.refresh(second.refreshToken());
    }

    @Test
    void reusedRefreshTokenRevokesWholeSession() {
        User user = user();
        TokenResponse first = authService.login(user.getUsername(), PASSWORD);
        TokenResponse second = authService.refresh(first.refreshToken());

        assertThrows(InvalidRefreshTokenException.class, () -> authService.refresh(first.refreshToken()));
        assertThrows(InvalidRefreshTokenException.class, () -> authService.refresh(second.refreshToken()));
    }

    @Test
    void unknownRefreshTokenIsRejected() {
        assertThrows(InvalidRefreshTokenException.class, () -> authService.refresh("nope"));
    }

    @Test
    void refreshIsRejectedForDisabledUser() {
        User user = user();
        TokenResponse response = authService.login(user.getUsername(), PASSWORD);
        user.setEnabled(false);
        users.save(user);

        assertThrows(InvalidRefreshTokenException.class, () -> authService.refresh(response.refreshToken()));
    }

    @Test
    void logoutRevokesRefreshToken() {
        User user = user();
        TokenResponse response = authService.login(user.getUsername(), PASSWORD);

        authService.logout(response.refreshToken());

        assertThrows(InvalidRefreshTokenException.class, () -> authService.refresh(response.refreshToken()));
    }

    private User user() {
        String username = "u" + UUID.randomUUID().toString().substring(0, 8);
        return users.save(new User(username, encoder.encode(PASSWORD), Role.USER));
    }
}

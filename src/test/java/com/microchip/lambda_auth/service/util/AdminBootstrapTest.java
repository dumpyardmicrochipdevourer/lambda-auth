package com.microchip.lambda_auth.service.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.microchip.lambda_auth.IntegrationTest;
import com.microchip.lambda_auth.config.AdminProperties;
import com.microchip.lambda_auth.domain.Role;
import com.microchip.lambda_auth.domain.User;
import com.microchip.lambda_auth.domain.repo.UserRepository;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;

class AdminBootstrapTest extends IntegrationTest {

    @Autowired UserRepository users;
    @Autowired PasswordEncoder encoder;
    @Autowired CredentialsValidator validator;

    @BeforeEach
    void noAdmins() {
        users.deleteAll(users.findAll().stream().filter(u -> u.getRole() == Role.ADMIN).toList());
    }

    @Test
    void createsAdminWhenNoneExists() {
        String username = name();

        bootstrap(username, "correct horse").run(null);

        User admin = users.findByUsernameIgnoreCase(username).orElseThrow();
        assertEquals(Role.ADMIN, admin.getRole());
        assertTrue(encoder.matches("correct horse", admin.getPasswordHash()));
    }

    @Test
    void doesNothingWhenAdminAlreadyExists() {
        bootstrap(name(), "correct horse").run(null);
        String other = name();

        bootstrap(other, "another horse").run(null);

        assertFalse(users.existsByUsernameIgnoreCase(other));
    }

    @Test
    void skipsWhenNotConfigured() {
        bootstrap("", "").run(null);
        bootstrap(null, null).run(null);

        assertFalse(users.existsByRole(Role.ADMIN));
    }

    @Test
    void failsOnWeakPassword() {
        AdminBootstrap bootstrap = bootstrap(name(), "short");

        assertThrows(IllegalArgumentException.class, () -> bootstrap.run(null));
        assertFalse(users.existsByRole(Role.ADMIN));
    }

    private AdminBootstrap bootstrap(String username, String password) {
        return new AdminBootstrap(new AdminProperties(username, password), users, encoder, validator);
    }

    private static String name() {
        return "admin_" + UUID.randomUUID().toString().substring(0, 8);
    }
}

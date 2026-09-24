package com.microchip.lambda_auth.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.microchip.lambda_auth.IntegrationTest;
import com.microchip.lambda_auth.domain.Invite;
import com.microchip.lambda_auth.domain.Role;
import com.microchip.lambda_auth.domain.User;
import com.microchip.lambda_auth.domain.dto.TokenResponse;
import com.microchip.lambda_auth.domain.repo.InviteRepository;
import com.microchip.lambda_auth.domain.repo.UserRepository;
import com.microchip.lambda_auth.service.exceptions.InvalidInviteException;
import com.microchip.lambda_auth.service.exceptions.UsernameTakenException;
import com.microchip.lambda_auth.service.util.InviteCodeGenerator;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

class RegistrationServiceTest extends IntegrationTest {

    private static final String PASSWORD = "correct horse";

    @Autowired RegistrationService registration;
    @Autowired UserRepository users;
    @Autowired InviteRepository invites;
    @Autowired InviteCodeGenerator codes;

    @Test
    void registersUserAndBurnsInvite() {
        Invite invite = invite(Duration.ofDays(1));
        String username = name();

        TokenResponse response = registration.register(invite.getCode(), username, PASSWORD);

        User user = users.findByUsernameIgnoreCase(username).orElseThrow();
        assertEquals(Role.USER, user.getRole());
        assertNotNull(response.accessToken());
        assertNotNull(response.refreshToken());
        assertEquals(user.getId(), invites.findByCode(invite.getCode()).orElseThrow().getUsedBy());
    }

    @Test
    void inviteWorksOnlyOnce() {
        Invite invite = invite(Duration.ofDays(1));
        registration.register(invite.getCode(), name(), PASSWORD);
        String second = name();

        assertThrows(InvalidInviteException.class, () -> registration.register(invite.getCode(), second, PASSWORD));
        assertFalse(users.existsByUsernameIgnoreCase(second));
    }

    @Test
    void expiredAndUnknownInvitesAreRejected() {
        Invite expired = invite(Duration.ofSeconds(-1));
        String username = name();

        assertThrows(InvalidInviteException.class, () -> registration.register(expired.getCode(), username, PASSWORD));
        assertThrows(InvalidInviteException.class, () -> registration.register("nope", username, PASSWORD));
        assertFalse(users.existsByUsernameIgnoreCase(username));
    }

    @Test
    void takenUsernameIsRejectedCaseInsensitivelyAndKeepsInvite() {
        String taken = name();
        registration.register(invite(Duration.ofDays(1)).getCode(), taken, PASSWORD);
        Invite fresh = invite(Duration.ofDays(1));

        assertThrows(UsernameTakenException.class,
                () -> registration.register(fresh.getCode(), taken.toUpperCase(), PASSWORD));
        assertNull(invites.findByCode(fresh.getCode()).orElseThrow().getUsedBy());
    }

    @Test
    void badCredentialsAreRejectedBeforeAnythingIsSpent() {
        Invite invite = invite(Duration.ofDays(1));

        assertThrows(IllegalArgumentException.class, () -> registration.register(invite.getCode(), "ab", PASSWORD));
        assertThrows(IllegalArgumentException.class, () -> registration.register(invite.getCode(), name(), "short"));
        assertTrue(invites.existsByCodeAndUsedAtIsNullAndExpiresAtAfter(invite.getCode(), Instant.now()));
    }

    @Test
    void concurrentRegistrationsOnOneInviteYieldExactlyOneUser() throws Exception {
        Invite invite = invite(Duration.ofDays(1));
        int attempts = 8;
        List<String> names = new ArrayList<>();
        for (int i = 0; i < attempts; i++) {
            names.add(name());
        }
        CountDownLatch start = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(attempts);

        List<Future<Boolean>> results = new ArrayList<>();
        for (String username : names) {
            results.add(pool.submit(() -> {
                start.await();
                try {
                    registration.register(invite.getCode(), username, PASSWORD);
                    return true;
                } catch (InvalidInviteException e) {
                    return false;
                }
            }));
        }
        start.countDown();

        int succeeded = 0;
        for (Future<Boolean> result : results) {
            if (result.get()) {
                succeeded++;
            }
        }
        pool.shutdown();

        assertEquals(1, succeeded);
        assertEquals(1, names.stream().filter(users::existsByUsernameIgnoreCase).count());
    }

    private Invite invite(Duration ttl) {
        User creator = users.save(new User(name(), "hash", Role.USER));
        return invites.save(new Invite(codes.generate(), creator.getId(), Instant.now().plus(ttl)));
    }

    private static String name() {
        return "u" + UUID.randomUUID().toString().substring(0, 8);
    }
}

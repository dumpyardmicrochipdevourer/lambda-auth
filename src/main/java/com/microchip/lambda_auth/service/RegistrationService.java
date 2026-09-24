package com.microchip.lambda_auth.service;

import com.microchip.lambda_auth.domain.Role;
import com.microchip.lambda_auth.domain.User;
import com.microchip.lambda_auth.domain.dto.TokenResponse;
import com.microchip.lambda_auth.domain.repo.InviteRepository;
import com.microchip.lambda_auth.domain.repo.UserRepository;
import com.microchip.lambda_auth.service.exceptions.InvalidInviteException;
import com.microchip.lambda_auth.service.exceptions.UsernameTakenException;
import com.microchip.lambda_auth.service.util.CredentialsValidator;
import java.time.Instant;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class RegistrationService {

    private final UserRepository userRepository;
    private final InviteRepository inviteRepository;
    private final AuthService authService;
    private final PasswordEncoder passwordEncoder;
    private final CredentialsValidator validator;

    public RegistrationService(
            UserRepository userRepository,
            InviteRepository inviteRepository,
            AuthService authService,
            PasswordEncoder passwordEncoder,
            CredentialsValidator validator) {
        this.userRepository = userRepository;
        this.inviteRepository = inviteRepository;
        this.authService = authService;
        this.passwordEncoder = passwordEncoder;
        this.validator = validator;
    }

    @Transactional
    public TokenResponse register(String inviteCode, String username, String password) {
        validator.validate(username, password);
        Instant now = Instant.now();

        if (!inviteRepository.existsByCodeAndUsedAtIsNullAndExpiresAtAfter(inviteCode, now)) {
            throw new InvalidInviteException();
        }
        if (userRepository.existsByUsernameIgnoreCase(username)) {
            throw new UsernameTakenException(username);
        }

        User user;
        try {
            user = userRepository.saveAndFlush(new User(username, passwordEncoder.encode(password), Role.USER));
        } catch (DataIntegrityViolationException e) {
            throw new UsernameTakenException(username);
        }

        if (inviteRepository.redeem(inviteCode, user.getId(), now) == 0) {
            throw new InvalidInviteException();
        }
        return authService.issueTokens(user);
    }
}

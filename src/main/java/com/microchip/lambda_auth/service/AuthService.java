package com.microchip.lambda_auth.service;

import com.microchip.lambda_auth.config.SessionProperties;
import com.microchip.lambda_auth.domain.RefreshToken;
import com.microchip.lambda_auth.domain.User;
import com.microchip.lambda_auth.domain.dto.TokenResponse;
import com.microchip.lambda_auth.domain.repo.RefreshTokenRepository;
import com.microchip.lambda_auth.domain.repo.UserRepository;
import com.microchip.lambda_auth.service.exceptions.InvalidCredentialsException;
import com.microchip.lambda_auth.service.exceptions.InvalidRefreshTokenException;
import com.microchip.lambda_auth.service.util.RefreshTokenGenerator;
import java.time.Instant;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final RefreshTokenGenerator tokenGenerator;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final SessionProperties sessionProperties;
    private final String dummyHash;

    public AuthService(
            UserRepository userRepository,
            RefreshTokenRepository refreshTokenRepository,
            RefreshTokenGenerator tokenGenerator,
            JwtService jwtService,
            PasswordEncoder passwordEncoder,
            SessionProperties sessionProperties) {
        this.userRepository = userRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.tokenGenerator = tokenGenerator;
        this.jwtService = jwtService;
        this.passwordEncoder = passwordEncoder;
        this.sessionProperties = sessionProperties;
        this.dummyHash = passwordEncoder.encode("dummy");
    }

    @Transactional
    public TokenResponse login(String username, String password) {
        User user = userRepository.findByUsernameIgnoreCase(username).orElse(null);
        boolean matches = passwordEncoder.matches(password, user != null ? user.getPasswordHash() : dummyHash);
        if (user == null || !matches || !user.isEnabled()) {
            throw new InvalidCredentialsException();
        }
        return issueTokens(user);
    }

    @Transactional(noRollbackFor = InvalidRefreshTokenException.class)
    public TokenResponse refresh(String refreshToken) {
        String hash = tokenGenerator.hash(refreshToken);
        Instant now = Instant.now();

        RefreshToken stored = refreshTokenRepository.findByTokenHash(hash)
                .orElseThrow(InvalidRefreshTokenException::new);

        if (refreshTokenRepository.revoke(hash, now) == 0) {
            if (stored.getRevokedAt() != null) {
                refreshTokenRepository.revokeAll(stored.getUserId(), now);
            }
            throw new InvalidRefreshTokenException();
        }

        User user = userRepository.findById(stored.getUserId())
                .filter(User::isEnabled)
                .orElseThrow(InvalidRefreshTokenException::new);
        return issueTokens(user);
    }

    @Transactional
    public void logout(String refreshToken) {
        refreshTokenRepository.revoke(tokenGenerator.hash(refreshToken), Instant.now());
    }

    @Transactional
    public TokenResponse issueTokens(User user) {
        String refreshToken = tokenGenerator.generate();
        Instant expiresAt = Instant.now().plus(sessionProperties.refreshTtl());
        refreshTokenRepository.save(new RefreshToken(user.getId(), tokenGenerator.hash(refreshToken), expiresAt));
        return new TokenResponse(jwtService.issue(user), refreshToken, jwtService.accessTtl().toSeconds());
    }
}

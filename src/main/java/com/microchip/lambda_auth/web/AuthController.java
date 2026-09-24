package com.microchip.lambda_auth.web;

import com.microchip.lambda_auth.domain.dto.LoginRequest;
import com.microchip.lambda_auth.domain.dto.RefreshRequest;
import com.microchip.lambda_auth.domain.dto.RegisterRequest;
import com.microchip.lambda_auth.domain.dto.TokenResponse;
import com.microchip.lambda_auth.service.AuthService;
import com.microchip.lambda_auth.service.RegistrationService;
import com.microchip.lambda_auth.service.exceptions.InvalidCredentialsException;
import com.microchip.lambda_auth.service.exceptions.InvalidInviteException;
import com.microchip.lambda_auth.service.exceptions.InvalidRefreshTokenException;
import com.microchip.lambda_auth.service.exceptions.UsernameTakenException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;
    private final RegistrationService registrationService;

    public AuthController(AuthService authService, RegistrationService registrationService) {
        this.authService = authService;
        this.registrationService = registrationService;
    }

    @PostMapping("/register")
    public TokenResponse register(@RequestBody RegisterRequest request) {
        return registrationService.register(
                required(request.inviteCode(), "inviteCode"), request.username(), request.password());
    }

    @PostMapping("/login")
    public TokenResponse login(@RequestBody LoginRequest request) {
        return authService.login(required(request.username(), "username"), required(request.password(), "password"));
    }

    @PostMapping("/refresh")
    public TokenResponse refresh(@RequestBody RefreshRequest request) {
        return authService.refresh(required(request.refreshToken(), "refreshToken"));
    }

    @PostMapping("/logout")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void logout(@RequestBody RefreshRequest request) {
        authService.logout(required(request.refreshToken(), "refreshToken"));
    }

    private static String required(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " обязателен");
        }
        return value;
    }

    @ExceptionHandler(InvalidCredentialsException.class)
    ProblemDetail handleInvalidCredentials(InvalidCredentialsException e) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.UNAUTHORIZED, e.getMessage());
    }

    @ExceptionHandler(InvalidRefreshTokenException.class)
    ProblemDetail handleInvalidRefreshToken(InvalidRefreshTokenException e) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.UNAUTHORIZED, e.getMessage());
    }

    @ExceptionHandler(InvalidInviteException.class)
    ProblemDetail handleInvalidInvite(InvalidInviteException e) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.FORBIDDEN, e.getMessage());
    }

    @ExceptionHandler(UsernameTakenException.class)
    ProblemDetail handleUsernameTaken(UsernameTakenException e) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.CONFLICT, e.getMessage());
    }

    @ExceptionHandler(IllegalArgumentException.class)
    ProblemDetail handleBadRequest(IllegalArgumentException e) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, e.getMessage());
    }
}

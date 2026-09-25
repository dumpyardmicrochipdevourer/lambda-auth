package com.microchip.lambda_auth.web;

import com.microchip.lambda_auth.domain.dto.CreateInviteRequest;
import com.microchip.lambda_auth.domain.dto.InviteView;
import com.microchip.lambda_auth.service.InviteService;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/invites")
public class InviteController {

    private static final int DEFAULT_TTL_DAYS = 7;
    private static final int MAX_TTL_DAYS = 30;

    private final InviteService inviteService;

    public InviteController(InviteService inviteService) {
        this.inviteService = inviteService;
    }

    @PostMapping
    public InviteView create(
            @AuthenticationPrincipal Jwt jwt,
            @RequestBody(required = false) CreateInviteRequest request) {
        int ttlDays = request == null || request.ttlDays() == null ? DEFAULT_TTL_DAYS : request.ttlDays();
        if (ttlDays < 1 || ttlDays > MAX_TTL_DAYS) {
            throw new IllegalArgumentException("ttlDays должен быть от 1 до " + MAX_TTL_DAYS);
        }
        return inviteService.create(UUID.fromString(jwt.getSubject()), Duration.ofDays(ttlDays));
    }

    @GetMapping
    public List<InviteView> list(@AuthenticationPrincipal Jwt jwt) {
        return inviteService.list(UUID.fromString(jwt.getSubject()));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    ProblemDetail handleBadRequest(IllegalArgumentException e) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, e.getMessage());
    }
}

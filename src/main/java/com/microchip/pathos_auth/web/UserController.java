package com.microchip.pathos_auth.web;

import com.microchip.pathos_auth.domain.dto.UpdateUserRequest;
import com.microchip.pathos_auth.domain.dto.UserView;
import com.microchip.pathos_auth.service.UserService;
import com.microchip.pathos_auth.service.exceptions.UserNotFoundException;
import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/users")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping
    public List<UserView> list() {
        return userService.list();
    }

    @GetMapping("/services")
    public List<String> services() {
        return userService.services();
    }

    @PatchMapping("/{id}")
    public UserView update(
            @AuthenticationPrincipal Jwt jwt,
            @PathVariable UUID id,
            @RequestBody UpdateUserRequest request) {
        if (request.enabled() == null && request.access() == null) {
            throw new IllegalArgumentException("нужен enabled или access");
        }
        UserView view = null;
        if (request.access() != null) {
            view = userService.setAccess(id, request.access());
        }
        if (request.enabled() != null) {
            view = userService.setEnabled(UUID.fromString(jwt.getSubject()), id, request.enabled());
        }
        return view;
    }

    @ExceptionHandler(UserNotFoundException.class)
    ProblemDetail handleNotFound(UserNotFoundException e) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.NOT_FOUND, e.getMessage());
    }

    @ExceptionHandler(IllegalArgumentException.class)
    ProblemDetail handleBadRequest(IllegalArgumentException e) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, e.getMessage());
    }
}

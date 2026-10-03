package com.microchip.lambda_auth.config;

import com.microchip.lambda_auth.domain.repo.InviteRepository;
import com.microchip.lambda_auth.domain.repo.RefreshTokenRepository;
import com.microchip.lambda_auth.domain.repo.UserRepository;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.binder.MeterBinder;
import java.time.Instant;
import org.springframework.stereotype.Component;

@Component
public class AuthMetrics implements MeterBinder {

    private final UserRepository users;
    private final RefreshTokenRepository sessions;
    private final InviteRepository invites;

    public AuthMetrics(UserRepository users, RefreshTokenRepository sessions, InviteRepository invites) {
        this.users = users;
        this.sessions = sessions;
        this.invites = invites;
    }

    @Override
    public void bindTo(MeterRegistry registry) {
        Gauge.builder("lambda.auth.users", users, UserRepository::count).register(registry);
        Gauge.builder("lambda.auth.sessions", sessions,
                s -> s.countByRevokedAtIsNullAndExpiresAtAfter(Instant.now())).register(registry);
        Gauge.builder("lambda.auth.invites", invites, InviteRepository::count).register(registry);
    }
}

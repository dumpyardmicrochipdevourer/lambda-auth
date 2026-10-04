package com.microchip.pathos_auth.config;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

@ConfigurationProperties(prefix = "pathos.auth.jwt")
public record JwtProperties(
        String privateKeyPath,
        @DefaultValue("http://localhost:8081") String issuer,
        @DefaultValue("pathos-auth-1") String keyId,
        @DefaultValue("10m") Duration accessTtl) {
}

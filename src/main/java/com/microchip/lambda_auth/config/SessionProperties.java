package com.microchip.lambda_auth.config;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

@ConfigurationProperties(prefix = "lambda.auth.session")
public record SessionProperties(@DefaultValue("30d") Duration refreshTtl) {
}

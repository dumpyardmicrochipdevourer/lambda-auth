package com.microchip.lambda_auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "lambda.auth.admin")
public record AdminProperties(String username, String password) {
}

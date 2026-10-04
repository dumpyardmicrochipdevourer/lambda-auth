package com.microchip.pathos_auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "pathos.auth.admin")
public record AdminProperties(String username, String password) {
}

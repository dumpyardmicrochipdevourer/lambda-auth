package com.microchip.lambda_auth.config;

import com.microchip.lambda_auth.service.util.RsaKeyLoader;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import java.nio.file.Path;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

@Configuration
@EnableConfigurationProperties(JwtProperties.class)
public class JwtConfiguration {

    @Bean
    RSAKey jwtKey(JwtProperties properties) {
        return RsaKeyLoader.load(Path.of(properties.privateKeyPath()), properties.keyId());
    }

    @Bean
    JwtEncoder jwtEncoder(RSAKey jwtKey) {
        return new NimbusJwtEncoder(new ImmutableJWKSet<>(new JWKSet(jwtKey)));
    }
}

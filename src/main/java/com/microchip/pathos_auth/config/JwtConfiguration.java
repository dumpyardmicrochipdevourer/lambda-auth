package com.microchip.pathos_auth.config;

import com.microchip.pathos_auth.service.util.RsaKeyLoader;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import java.nio.file.Path;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
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

    @Bean
    JwtDecoder jwtDecoder(RSAKey jwtKey, JwtProperties properties) throws JOSEException {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withPublicKey(jwtKey.toRSAPublicKey()).build();
        decoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(properties.issuer()));
        return decoder;
    }
}

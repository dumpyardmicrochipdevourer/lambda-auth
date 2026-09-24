package com.microchip.lambda_auth.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.microchip.lambda_auth.TestKeys;
import com.microchip.lambda_auth.config.JwtProperties;
import com.microchip.lambda_auth.domain.Role;
import com.microchip.lambda_auth.domain.User;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import java.time.Duration;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.test.util.ReflectionTestUtils;

class JwtServiceTest {

    private static final JwtProperties PROPERTIES =
            new JwtProperties("unused", "https://auth.lambda.test", "test-key", Duration.ofMinutes(10));

    @Test
    void issuedTokenVerifiesWithPublicKey() throws Exception {
        RSAKey key = TestKeys.rsaKey(TestKeys.generate(), "test-key");
        User user = new User("kolya", "hash", Role.ADMIN);
        UUID id = UUID.randomUUID();
        ReflectionTestUtils.setField(user, "id", id);

        Jwt jwt = NimbusJwtDecoder.withPublicKey(key.toRSAPublicKey()).build().decode(service(key).issue(user));

        assertEquals(id.toString(), jwt.getSubject());
        assertEquals("kolya", jwt.getClaimAsString("username"));
        assertEquals("ADMIN", jwt.getClaimAsString("role"));
        assertEquals("https://auth.lambda.test", jwt.getIssuer().toString());
        assertEquals("test-key", jwt.getHeaders().get("kid"));
    }

    @Test
    void tokenSignedWithForeignKeyIsRejected() throws Exception {
        RSAKey key = TestKeys.rsaKey(TestKeys.generate(), "test-key");
        RSAKey foreign = TestKeys.rsaKey(TestKeys.generate(), "test-key");
        User user = new User("kolya", "hash", Role.USER);
        ReflectionTestUtils.setField(user, "id", UUID.randomUUID());

        String token = service(key).issue(user);

        assertThrows(JwtException.class,
                () -> NimbusJwtDecoder.withPublicKey(foreign.toRSAPublicKey()).build().decode(token));
    }

    private JwtService service(RSAKey key) {
        return new JwtService(new NimbusJwtEncoder(new ImmutableJWKSet<>(new JWKSet(key))), PROPERTIES);
    }
}

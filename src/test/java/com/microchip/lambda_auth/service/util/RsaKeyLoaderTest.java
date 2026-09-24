package com.microchip.lambda_auth.service.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.microchip.lambda_auth.TestKeys;
import com.microchip.lambda_auth.web.JwksController;
import com.nimbusds.jose.jwk.RSAKey;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class RsaKeyLoaderTest {

    @Test
    void loadsPrivateKeyAndDerivesPublicOne() throws Exception {
        KeyPair pair = TestKeys.generate();

        RSAKey key = RsaKeyLoader.load(TestKeys.writePem(pair), "kid-1");

        assertEquals(((RSAPublicKey) pair.getPublic()).getModulus(), key.toRSAPublicKey().getModulus());
        assertEquals("kid-1", key.getKeyID());
        assertNotNull(key.toPrivateKey());
    }

    @Test
    void rejectsGarbage() throws IOException {
        Path file = Files.createTempFile("jwt-garbage", ".pem");
        file.toFile().deleteOnExit();
        Files.writeString(file, "not a key");

        assertThrows(IllegalStateException.class, () -> RsaKeyLoader.load(file, "kid-1"));
    }

    @Test
    void jwksExposesOnlyPublicPart() {
        RSAKey key = RsaKeyLoader.load(TestKeys.writePem(TestKeys.generate()), "kid-1");

        Map<String, Object> jwks = new JwksController(key).jwks();

        Map<?, ?> jwk = (Map<?, ?>) ((List<?>) jwks.get("keys")).get(0);
        assertEquals("kid-1", jwk.get("kid"));
        assertFalse(jwk.containsKey("d"));
    }
}

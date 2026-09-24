package com.microchip.lambda_auth.service.util;

import com.nimbusds.jose.jwk.RSAKey;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

public final class RsaKeyLoader {

    private RsaKeyLoader() {}

    public static RSAKey load(Path path, String keyId) {
        try {
            String body = Files.readString(path)
                    .replaceAll("-----[A-Z ]+-----", "")
                    .replaceAll("\\s", "");
            KeyFactory factory = KeyFactory.getInstance("RSA");
            PrivateKey key = factory.generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(body)));
            if (!(key instanceof RSAPrivateCrtKey crt)) {
                throw new IllegalStateException("ключ " + path + " не RSA с CRT-параметрами");
            }
            RSAPublicKey publicKey = (RSAPublicKey) factory.generatePublic(
                    new RSAPublicKeySpec(crt.getModulus(), crt.getPublicExponent()));
            return new RSAKey.Builder(publicKey).privateKey(crt).keyID(keyId).build();
        } catch (IOException e) {
            throw new UncheckedIOException("не удалось прочитать ключ " + path, e);
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new IllegalStateException("ключ " + path + " не в формате PKCS8 PEM", e);
        }
    }
}

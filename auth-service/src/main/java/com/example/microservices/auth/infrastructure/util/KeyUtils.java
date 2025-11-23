package com.example.microservices.auth.infrastructure.util;

import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.Resource;

import java.io.IOException;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Utility class for loading RSA keys from classpath resources.
 * Used by
 * {@link com.example.microservices.auth.infrastructure.adapter.security.JwtTokenProvider}.
 */
@Slf4j
public class KeyUtils {

    /**
     * Loads an RSA private key from the given {@link Resource}.
     *
     * @param privateKeyResource resource containing the PEM encoded private key
     * @return {@link PrivateKey} instance
     * @throws Exception if the key cannot be loaded or parsed
     */
    public static PrivateKey loadPrivateKey(Resource privateKeyResource) throws Exception {
        try {
            String privateKeyPEM = new String(Files.readAllBytes(privateKeyResource.getFile().toPath()))
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");
            byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyPEM);
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePrivate(privateKeySpec);
        } catch (IOException e) {
            log.error("Error loading RSA private key", e);
            throw new RuntimeException("Error loading RSA private key", e);
        }
    }

    /**
     * Loads an RSA public key from the given {@link Resource}.
     *
     * @param publicKeyResource resource containing the PEM encoded public key
     * @return {@link PublicKey} instance
     * @throws Exception if the key cannot be loaded or parsed
     */
    public static PublicKey loadPublicKey(Resource publicKeyResource) throws Exception {
        try {
            String publicKeyPEM = new String(Files.readAllBytes(publicKeyResource.getFile().toPath()))
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s", "");
            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyPEM);
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePublic(publicKeySpec);
        } catch (IOException e) {
            log.error("Error loading RSA public key", e);
            throw new RuntimeException("Error loading RSA public key", e);
        }
    }
}

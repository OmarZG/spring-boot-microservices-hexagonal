package com.example.microservices.common.security;

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
 * Utility class for loading RSA keys from PEM files.
 * This class provides static methods to load RSA public and private keys
 * from classpath resources in PEM format.
 *
 * <p>
 * Usage example:
 * 
 * <pre>
 * {@code
 * Resource publicKeyResource = new ClassPathResource("certs/public_key.pem");
 * PublicKey publicKey = RsaKeyUtils.loadPublicKey(publicKeyResource);
 * }
 * </pre>
 */
@Slf4j
public final class RsaKeyUtils {

    private RsaKeyUtils() {
        throw new UnsupportedOperationException("Utility class cannot be instantiated");
    }

    /**
     * Loads an RSA private key from a PEM file.
     *
     * @param privateKeyResource Spring Resource containing the PEM encoded private
     *                           key
     * @return {@link PrivateKey} instance ready for use in cryptographic operations
     * @throws RsaKeyLoadException if the key cannot be loaded or parsed
     */
    public static PrivateKey loadPrivateKey(Resource privateKeyResource) {
        try {
            log.debug("Loading RSA private key from: {}", privateKeyResource.getFilename());

            String privateKeyPEM = new String(Files.readAllBytes(privateKeyResource.getFile().toPath()))
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");

            byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyPEM);
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
            log.info("RSA private key loaded successfully");

            return privateKey;
        } catch (IOException e) {
            log.error("Failed to read RSA private key file: {}", privateKeyResource.getFilename(), e);
            throw new RsaKeyLoadException("Failed to read RSA private key file", e);
        } catch (Exception e) {
            log.error("Failed to parse RSA private key", e);
            throw new RsaKeyLoadException("Failed to parse RSA private key", e);
        }
    }

    /**
     * Loads an RSA public key from a PEM file.
     *
     * @param publicKeyResource Spring Resource containing the PEM encoded public
     *                          key
     * @return {@link PublicKey} instance ready for use in cryptographic operations
     * @throws RsaKeyLoadException if the key cannot be loaded or parsed
     */
    public static PublicKey loadPublicKey(Resource publicKeyResource) {
        try {
            log.debug("Loading RSA public key from: {}", publicKeyResource.getFilename());

            String publicKeyPEM = new String(Files.readAllBytes(publicKeyResource.getFile().toPath()))
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s", "");

            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyPEM);
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
            log.info("RSA public key loaded successfully");

            return publicKey;
        } catch (IOException e) {
            log.error("Failed to read RSA public key file: {}", publicKeyResource.getFilename(), e);
            throw new RsaKeyLoadException("Failed to read RSA public key file", e);
        } catch (Exception e) {
            log.error("Failed to parse RSA public key", e);
            throw new RsaKeyLoadException("Failed to parse RSA public key", e);
        }
    }

    /**
     * Exception thrown when RSA key loading fails.
     */
    public static class RsaKeyLoadException extends RuntimeException {
        public RsaKeyLoadException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}

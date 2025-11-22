package com.example.microservices.product.infrastructure.adapter.security;

import io.jsonwebtoken.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;

import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * JWT Token Validator for product-service
 * Only validates tokens using public key (no token generation)
 */
@Slf4j
@Component
public class JwtTokenValidator {

    @Value("classpath:${jwt.public-key-path}")
    private Resource publicKeyResource;

    private PublicKey publicKey;

    /**
     * Get username from JWT token
     */
    public String getUsernameFromToken(String token) {
        try {
            if (publicKey == null) {
                loadPublicKey();
            }

            Claims claims = Jwts.parser()
                    .verifyWith(publicKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            return claims.getSubject();
        } catch (Exception e) {
            log.error("Error extracting username from token", e);
            return null;
        }
    }

    /**
     * Validate JWT token
     */
    public boolean validateToken(String token) {
        try {
            if (publicKey == null) {
                loadPublicKey();
            }

            Jwts.parser()
                    .verifyWith(publicKey)
                    .build()
                    .parseSignedClaims(token);

            return true;
        } catch (SecurityException ex) {
            log.error("Invalid JWT signature");
        } catch (MalformedJwtException ex) {
            log.error("Invalid JWT token");
        } catch (ExpiredJwtException ex) {
            log.error("Expired JWT token");
        } catch (UnsupportedJwtException ex) {
            log.error("Unsupported JWT token");
        } catch (IllegalArgumentException ex) {
            log.error("JWT claims string is empty");
        } catch (Exception ex) {
            log.error("JWT validation error", ex);
        }
        return false;
    }

    /**
     * Load RSA public key from file
     */
    private void loadPublicKey() throws Exception {
        try {
            String publicKeyPEM = new String(Files.readAllBytes(publicKeyResource.getFile().toPath()))
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s", "");

            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyPEM);
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            this.publicKey = keyFactory.generatePublic(publicKeySpec);

            log.info("RSA public key loaded successfully");
        } catch (Exception e) {
            log.error("Error loading RSA public key", e);
            throw new RuntimeException("Error loading RSA public key", e);
        }
    }
}

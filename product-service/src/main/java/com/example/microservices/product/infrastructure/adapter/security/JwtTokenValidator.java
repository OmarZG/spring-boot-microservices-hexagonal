package com.example.microservices.product.infrastructure.adapter.security;

import com.example.microservices.common.security.RsaKeyUtils;
import io.jsonwebtoken.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;

import java.security.PublicKey;

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
     * Get roles from JWT token
     */
    public java.util.List<String> getRolesFromToken(String token) {
        try {
            if (publicKey == null) {
                loadPublicKey();
            }

            Claims claims = Jwts.parser()
                    .verifyWith(publicKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            String rolesString = claims.get("roles", String.class);
            if (rolesString != null && !rolesString.isEmpty()) {
                return java.util.Arrays.asList(rolesString.split(","));
            }
            return java.util.Collections.emptyList();
        } catch (Exception e) {
            log.error("Error extracting roles from token", e);
            return java.util.Collections.emptyList();
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
     * Load RSA public key from file using RsaKeyUtils
     */
    private void loadPublicKey() {
        this.publicKey = RsaKeyUtils.loadPublicKey(publicKeyResource);
        log.info("RSA public key loaded successfully");
    }
}

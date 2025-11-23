package com.example.microservices.auth.infrastructure.adapter.security;

import io.jsonwebtoken.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.stream.Collectors;

/**
 * JWT Token Provider using RSA signature
 * Generates and validates JWT tokens
 */
@Slf4j
@Component
public class JwtTokenProvider {

    @Value("${jwt.expiration}")
    private Long jwtExpiration;

    @Value("${jwt.issuer}")
    private String jwtIssuer;

    @Value("classpath:${jwt.private-key-path}")
    private Resource privateKeyResource;

    @Value("classpath:${jwt.public-key-path}")
    private Resource publicKeyResource;

    private PrivateKey privateKey;
    private PublicKey publicKey;

    /**
     * Generate JWT token from authentication
     */
    public String generateToken(Authentication authentication) {
        try {
            if (privateKey == null) {
                loadKeys();
            }

            String username = authentication.getName();
            Date now = new Date();
            Date expiryDate = new Date(now.getTime() + jwtExpiration);

            String roles = authentication.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.joining(","));

            return Jwts.builder()
                    .subject(username)
                    .issuedAt(now)
                    .expiration(expiryDate)
                    .issuer(jwtIssuer)
                    .claim("roles", roles)
                    .signWith(privateKey, Jwts.SIG.RS256)
                    .compact();
        } catch (Exception e) {
            log.error("Error generating JWT token", e);
            throw new RuntimeException("Error generating JWT token", e);
        }
    }

    /**
     * Get username from JWT token
     */
    public String getUsernameFromToken(String token) {
        try {
            if (publicKey == null) {
                loadKeys();
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
                loadKeys();
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
     * Get expiration time in seconds
     */
    public Long getExpirationTime() {
        return jwtExpiration / 1000; // Convert to seconds
    }

    /**
     * Load RSA keys from files
     */
    private void loadKeys() throws Exception {
        // Delegate key loading to utility class
        this.privateKey = com.example.microservices.auth.infrastructure.util.KeyUtils
                .loadPrivateKey(privateKeyResource);
        this.publicKey = com.example.microservices.auth.infrastructure.util.KeyUtils.loadPublicKey(publicKeyResource);
        log.info("RSA keys loaded successfully");
    }
}

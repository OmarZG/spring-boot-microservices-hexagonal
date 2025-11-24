package com.example.microservices.auth.application.dto;

/**
 * Authentication response DTO using Java Record
 */
public record AuthResponse(
        String token,
        String type,
        Long expiresIn,
        UserDTO user) {
    /**
     * Creates an AuthResponse with Bearer token
     */
    public static AuthResponse of(String token, Long expiresIn, UserDTO user) {
        return new AuthResponse(token, "Bearer", expiresIn, user);
    }
}

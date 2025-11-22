package com.example.microservices.auth.domain.port.in;

import com.example.microservices.auth.domain.model.User;

/**
 * Input port for authentication use cases
 * This interface defines the business operations available
 */
public interface AuthUseCase {

    /**
     * Register a new user
     * 
     * @param user        User to register
     * @param rawPassword Plain text password
     * @return Registered user
     */
    User register(User user, String rawPassword);

    /**
     * Authenticate user and generate token
     * 
     * @param username Username or email
     * @param password Plain text password
     * @return JWT token
     */
    String login(String username, String password);

    /**
     * Validate JWT token
     * 
     * @param token JWT token
     * @return true if valid, false otherwise
     */
    boolean validateToken(String token);

    /**
     * Get username from token
     * 
     * @param token JWT token
     * @return Username
     */
    String getUsernameFromToken(String token);

    /**
     * Get current authenticated user
     * 
     * @return Current user
     */
    User getCurrentUser();
}

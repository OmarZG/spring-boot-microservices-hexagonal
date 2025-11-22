package com.example.microservices.auth.domain.port.out;

import com.example.microservices.auth.domain.model.User;

import java.util.Optional;

/**
 * Output port for User persistence operations
 * This interface defines the contract for the repository adapter
 */
public interface UserPort {

    /**
     * Save or update a user
     * 
     * @param user User to save
     * @return Saved user
     */
    User save(User user);

    /**
     * Find user by ID
     * 
     * @param id User ID
     * @return Optional containing user if found
     */
    Optional<User> findById(Long id);

    /**
     * Find user by username
     * 
     * @param username Username
     * @return Optional containing user if found
     */
    Optional<User> findByUsername(String username);

    /**
     * Find user by email
     * 
     * @param email Email address
     * @return Optional containing user if found
     */
    Optional<User> findByEmail(String email);

    /**
     * Check if username exists
     * 
     * @param username Username to check
     * @return true if exists, false otherwise
     */
    boolean existsByUsername(String username);

    /**
     * Check if email exists
     * 
     * @param email Email to check
     * @return true if exists, false otherwise
     */
    boolean existsByEmail(String email);

    /**
     * Delete user by ID
     * 
     * @param id User ID
     */
    void deleteById(Long id);
}

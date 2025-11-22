package com.example.microservices.auth.application.dto;

import com.example.microservices.auth.domain.enums.Role;

import java.time.LocalDateTime;
import java.util.Set;

/**
 * User DTO using Java Record (excludes sensitive data like password)
 */
public record UserDTO(
        Long id,
        String username,
        String email,
        Set<Role> roles,
        boolean enabled,
        LocalDateTime createdAt,
        LocalDateTime updatedAt) {
}

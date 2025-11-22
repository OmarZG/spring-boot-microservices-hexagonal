package com.example.microservices.auth.domain.model;

import com.example.microservices.auth.domain.enums.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.Set;

/**
 * Pure domain entity for User (framework-agnostic)
 * This is the core business model without any infrastructure dependencies
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class User {

    private Long id;
    private String username;
    private String email;
    private String password;
    private Set<Role> roles;
    private boolean enabled;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

    /**
     * Business validation: Check if user has a specific role
     */
    public boolean hasRole(Role role) {
        return roles != null && roles.contains(role);
    }

    /**
     * Business validation: Check if user is active
     */
    public boolean isActive() {
        return enabled;
    }

    /**
     * Business logic: Add a role to user
     */
    public void addRole(Role role) {
        if (this.roles == null) {
            this.roles = Set.of(role);
        } else {
            this.roles.add(role);
        }
    }

    /**
     * Business logic: Remove a role from user
     */
    public void removeRole(Role role) {
        if (this.roles != null) {
            this.roles.remove(role);
        }
    }
}

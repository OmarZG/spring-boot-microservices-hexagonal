package com.example.microservices.auth.domain.enums;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * User roles with associated authorities
 */
public enum Role {
    USER(Set.of(
            "user:read",
            "user:update")),
    MODERATOR(Set.of(
            "user:read",
            "user:update",
            "user:moderate",
            "product:read",
            "product:create",
            "product:update")),
    ADMIN(Set.of(
            "user:read",
            "user:create",
            "user:update",
            "user:delete",
            "product:read",
            "product:create",
            "product:update",
            "product:delete",
            "admin:all"));

    private final Set<String> permissions;

    Role(Set<String> permissions) {
        this.permissions = permissions;
    }

    public Set<String> getPermissions() {
        return permissions;
    }

    /**
     * Converts role and permissions to Spring Security GrantedAuthority
     * 
     * @return Collection of GrantedAuthority
     */
    public Collection<? extends GrantedAuthority> getAuthorities() {
        List<GrantedAuthority> authorities = permissions.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        // Add role itself as authority with ROLE_ prefix
        authorities.add(new SimpleGrantedAuthority("ROLE_" + this.name()));

        return authorities;
    }
}

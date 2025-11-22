package com.example.microservices.auth.application.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

/**
 * Login request DTO using Java Record
 */
public record LoginRequest(
        @NotBlank(message = "Username is required") String username,

        @NotBlank(message = "Password is required") String password) {
}

package com.example.microservices.auth.adapter.rest;

import com.example.microservices.auth.application.dto.AuthResponse;
import com.example.microservices.auth.application.dto.LoginRequest;
import com.example.microservices.auth.application.dto.RegisterRequest;
import com.example.microservices.auth.application.dto.UserDTO;
import com.example.microservices.auth.application.mapper.UserMapper;
import com.example.microservices.auth.application.service.AuthService;
import com.example.microservices.auth.domain.model.User;
import com.example.microservices.common.dto.ApiResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * REST Controller for authentication endpoints
 */
@Slf4j
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final UserMapper userMapper;

    /**
     * Register a new user
     */
    @PostMapping("/register")
    public ResponseEntity<ApiResponse<UserDTO>> register(@Valid @RequestBody RegisterRequest request) {
        log.info("Registration request for username: {}", request.username());

        User user = userMapper.toDomain(request);
        User registeredUser = authService.register(user, request.password());
        UserDTO userDTO = userMapper.toDTO(registeredUser);

        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(ApiResponse.success(userDTO, "User registered successfully"));
    }

    /**
     * Authenticate user and return JWT token
     */
    @PostMapping("/login")
    public ResponseEntity<ApiResponse<AuthResponse>> login(@Valid @RequestBody LoginRequest request) {
        log.info("Login request for username: {}", request.username());

        String token = authService.login(request.username(), request.password());
        User user = authService.getCurrentUser();
        UserDTO userDTO = userMapper.toDTO(user);

        AuthResponse authResponse = AuthResponse.of(token, authService.getExpirationTime(), userDTO);

        return ResponseEntity.ok(ApiResponse.success(authResponse, "Login successful"));
    }

    /**
     * Get current authenticated user
     */
    @GetMapping("/me")
    @org.springframework.security.access.prepost.PreAuthorize("hasAnyRole('USER', 'MODERATOR', 'ADMIN')")
    public ResponseEntity<ApiResponse<UserDTO>> getCurrentUser() {
        User user = authService.getCurrentUser();
        UserDTO userDTO = userMapper.toDTO(user);

        return ResponseEntity.ok(ApiResponse.success(userDTO));
    }
}

package com.example.microservices.auth.application.service;

import com.example.microservices.auth.application.adapter.UserDetailsAdapter;
import com.example.microservices.auth.application.dto.UserDTO;
import com.example.microservices.auth.application.mapper.UserMapper;
import com.example.microservices.auth.domain.exception.InvalidCredentialsException;
import com.example.microservices.auth.domain.exception.UserAlreadyExistsException;
import com.example.microservices.auth.domain.exception.UserNotFoundException;
import com.example.microservices.auth.domain.model.User;
import com.example.microservices.auth.domain.port.in.AuthUseCase;
import com.example.microservices.auth.domain.port.out.UserPort;
import com.example.microservices.auth.infrastructure.adapter.security.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Authentication service implementation
 * Orchestrates authentication business logic
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService implements AuthUseCase {

    private final UserPort userPort;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final AuthenticationManager authenticationManager;
    private final UserMapper userMapper;

    @Override
    @Transactional
    public User register(User user, String rawPassword) {
        log.info("Registering new user: {}", user.getUsername());

        // Check if username already exists
        if (userPort.existsByUsername(user.getUsername())) {
            throw UserAlreadyExistsException.byUsername(user.getUsername());
        }

        // Check if email already exists
        if (userPort.existsByEmail(user.getEmail())) {
            throw UserAlreadyExistsException.byEmail(user.getEmail());
        }

        // Encode password
        user.setPassword(passwordEncoder.encode(rawPassword));
        user.setEnabled(true);

        // Save user
        User savedUser = userPort.save(user);
        log.info("User registered successfully: {}", savedUser.getUsername());

        return savedUser;
    }

    @Override
    public String login(String username, String password) {
        log.info("Attempting login for user: {}", username);

        try {
            // Authenticate user
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password));

            SecurityContextHolder.getContext().setAuthentication(authentication);

            // Generate JWT token
            String token = jwtTokenProvider.generateToken(authentication);
            log.info("User logged in successfully: {}", username);

            return token;
        } catch (Exception e) {
            log.error("Login failed for user: {}", username, e);
            throw new InvalidCredentialsException();
        }
    }

    @Override
    public boolean validateToken(String token) {
        return jwtTokenProvider.validateToken(token);
}

@Override
    public String getUsernameFromToken(String token) {
package com.example.microservices.auth.application.service;

import com.example.microservices.auth.application.adapter.UserDetailsAdapter;
import com.example.microservices.auth.application.dto.UserDTO;
import com.example.microservices.auth.application.mapper.UserMapper;
import com.example.microservices.auth.domain.exception.InvalidCredentialsException;
import com.example.microservices.auth.domain.exception.UserAlreadyExistsException;
import com.example.microservices.auth.domain.exception.UserNotFoundException;
import com.example.microservices.auth.domain.model.User;
import com.example.microservices.auth.domain.port.in.AuthUseCase;
import com.example.microservices.auth.domain.port.out.UserPort;
import com.example.microservices.auth.infrastructure.adapter.security.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Authentication service implementation
 * Orchestrates authentication business logic
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService implements AuthUseCase {

    private final UserPort userPort;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final AuthenticationManager authenticationManager;
    private final UserMapper userMapper;

    @Override
    @Transactional
    public User register(User user, String rawPassword) {
        log.info("Registering new user: {}", user.getUsername());

        // Check if username already exists
        if (userPort.existsByUsername(user.getUsername())) {
            throw UserAlreadyExistsException.byUsername(user.getUsername());
        }

        // Check if email already exists
        if (userPort.existsByEmail(user.getEmail())) {
            throw UserAlreadyExistsException.byEmail(user.getEmail());
        }

        // Encode password
        user.setPassword(passwordEncoder.encode(rawPassword));
        user.setEnabled(true);

        // Save user
        User savedUser = userPort.save(user);
        log.info("User registered successfully: {}", savedUser.getUsername());

        return savedUser;
    }

    @Override
    public String login(String username, String password) {
        log.info("Attempting login for user: {}", username);

        try {
            // Authenticate user
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password));

            SecurityContextHolder.getContext().setAuthentication(authentication);

            // Generate JWT token
            String token = jwtTokenProvider.generateToken(authentication);
            log.info("User logged in successfully: {}", username);

            return token;
        } catch (Exception e) {
            log.error("Login failed for user: {}", username, e);
            throw new InvalidCredentialsException();
        }
    }

    @Override
    public boolean validateToken(String token) {
        return jwtTokenProvider.validateToken(token);
    }

    @Override
    public String getUsernameFromToken(String token) {
        return jwtTokenProvider.getUsernameFromToken(token);
    }

    @Override
    public User getCurrentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()) {
            throw new InvalidCredentialsException("No authenticated user found");
        }

        String username = authentication.getName();
        return userPort.findByUsername(username)
                .orElseThrow(() -> new UserNotFoundException("username", username));
    }

    /**
     * Get JWT token expiration time in seconds
     */
    public Long getExpirationTime() {
        return jwtTokenProvider.getExpirationTime();
    }
}

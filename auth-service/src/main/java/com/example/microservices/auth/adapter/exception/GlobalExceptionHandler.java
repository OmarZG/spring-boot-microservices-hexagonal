package com.example.microservices.auth.adapter.exception;

import com.example.microservices.auth.domain.exception.InvalidCredentialsException;
import com.example.microservices.auth.domain.exception.UserAlreadyExistsException;
import com.example.microservices.auth.domain.exception.UserNotFoundException;
import com.example.microservices.common.dto.ErrorResponse;
import com.example.microservices.common.exception.BaseGlobalExceptionHandler;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.Instant;

/**
 * Global exception handler for auth-service.
 * Extends {@link BaseGlobalExceptionHandler} to inherit common exception
 * handling
 * and adds auth-service specific exception handlers.
 */
@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler extends BaseGlobalExceptionHandler {

        /**
         * Handle user not found exception
         */
        @ExceptionHandler(UserNotFoundException.class)
        public ResponseEntity<ErrorResponse> handleUserNotFound(UserNotFoundException ex) {
                log.error("User not found: {}", ex.getMessage());

                ErrorResponse errorResponse = ErrorResponse.builder()
                                .errorCode("USER_NOT_FOUND")
                                .message(ex.getMessage())
                                .status(HttpStatus.NOT_FOUND.value())
                                .timestamp(Instant.now())
                                .build();

                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(errorResponse);
        }

        /**
         * Handle user already exists exception
         */
        @ExceptionHandler(UserAlreadyExistsException.class)
        public ResponseEntity<ErrorResponse> handleUserAlreadyExists(UserAlreadyExistsException ex) {
                log.error("User already exists: {}", ex.getMessage());

                ErrorResponse errorResponse = ErrorResponse.builder()
                                .errorCode("USER_ALREADY_EXISTS")
                                .message(ex.getMessage())
                                .status(HttpStatus.CONFLICT.value())
                                .timestamp(Instant.now())
                                .build();

                return ResponseEntity.status(HttpStatus.CONFLICT).body(errorResponse);
        }

        /**
         * Handle invalid credentials exception
         */
        @ExceptionHandler(InvalidCredentialsException.class)
        public ResponseEntity<ErrorResponse> handleInvalidCredentials(InvalidCredentialsException ex) {
                log.error("Invalid credentials: {}", ex.getMessage());

                ErrorResponse errorResponse = ErrorResponse.builder()
                                .errorCode("INVALID_CREDENTIALS")
                                .message(ex.getMessage())
                                .status(HttpStatus.UNAUTHORIZED.value())
                                .timestamp(Instant.now())
                                .build();

                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
        }
}

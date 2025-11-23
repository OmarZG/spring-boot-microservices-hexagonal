package com.example.microservices.common.exception;

import com.example.microservices.common.dto.ErrorResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.Instant;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Base exception handler with common exception handling logic.
 * All microservices should extend this class to inherit common error handling
 * and add their service-specific exception handlers.
 *
 * <p>
 * This class handles:
 * <ul>
 * <li>Validation errors ({@link MethodArgumentNotValidException})</li>
 * <li>Authentication errors ({@link AuthenticationException})</li>
 * <li>Authorization errors ({@link AccessDeniedException})</li>
 * <li>Generic exceptions ({@link Exception})</li>
 * </ul>
 *
 * <p>
 * Usage example:
 * 
 * <pre>
 * {
 *     &#64;code
 *     &#64;RestControllerAdvice
 *     public class MyServiceExceptionHandler extends BaseGlobalExceptionHandler {
 *         @ExceptionHandler(MyCustomException.class)
 *         public ResponseEntity<ErrorResponse> handleMyCustomException(MyCustomException ex) {
 *             // Handle service-specific exception
 *         }
 *     }
 * }
 * </pre>
 */
@Slf4j
@RestControllerAdvice
public abstract class BaseGlobalExceptionHandler {

    /**
     * Handle validation errors from
     * {@link org.springframework.validation.annotation.Validated}
     * and {@link jakarta.validation.Valid} annotations.
     *
     * @param ex the validation exception
     * @return response entity with validation error details
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleValidationErrors(MethodArgumentNotValidException ex) {
        log.error("Validation error: {}", ex.getMessage());

        List<ErrorResponse.FieldError> fieldErrors = ex.getBindingResult()
                .getFieldErrors()
                .stream()
                .map(error -> ErrorResponse.FieldError.builder()
                        .field(error.getField())
                        .message(error.getDefaultMessage())
                        .rejectedValue(error.getRejectedValue())
                        .build())
                .collect(Collectors.toList());

        ErrorResponse errorResponse = ErrorResponse.builder()
                .errorCode("VALIDATION_ERROR")
                .message("Validation failed")
                .status(HttpStatus.BAD_REQUEST.value())
                .fieldErrors(fieldErrors)
                .timestamp(Instant.now())
                .build();

        return ResponseEntity.badRequest().body(errorResponse);
    }

    /**
     * Handle authentication exceptions from Spring Security.
     *
     * @param ex the authentication exception
     * @return response entity with authentication error
     */
    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ErrorResponse> handleAuthenticationException(AuthenticationException ex) {
        log.error("Authentication error: {}", ex.getMessage());

        ErrorResponse errorResponse = ErrorResponse.builder()
                .errorCode("AUTHENTICATION_ERROR")
                .message("Authentication failed")
                .status(HttpStatus.UNAUTHORIZED.value())
                .timestamp(Instant.now())
                .build();

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
    }

    /**
     * Handle access denied exceptions from Spring Security.
     * This occurs when an authenticated user tries to access a resource
     * they don't have permission for.
     *
     * @param ex the access denied exception
     * @return response entity with access denied error
     */
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ErrorResponse> handleAccessDenied(AccessDeniedException ex) {
        log.error("Access denied: {}", ex.getMessage());

        ErrorResponse errorResponse = ErrorResponse.builder()
                .errorCode("ACCESS_DENIED")
                .message("Access denied")
                .status(HttpStatus.FORBIDDEN.value())
                .timestamp(Instant.now())
                .build();

        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(errorResponse);
    }

    /**
     * Handle all other unhandled exceptions.
     * This is the catch-all handler that should be overridden carefully.
     *
     * @param ex the generic exception
     * @return response entity with internal server error
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleGenericException(Exception ex) {
        log.error("Unexpected error", ex);

        ErrorResponse errorResponse = ErrorResponse.builder()
                .errorCode("INTERNAL_SERVER_ERROR")
                .message("An unexpected error occurred")
                .status(HttpStatus.INTERNAL_SERVER_ERROR.value())
                .timestamp(Instant.now())
                .build();

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
    }
}

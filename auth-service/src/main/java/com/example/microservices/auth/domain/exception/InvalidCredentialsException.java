package com.example.microservices.auth.domain.exception;

/**
 * Exception thrown when credentials are invalid
 */
public class InvalidCredentialsException extends DomainException {

    public InvalidCredentialsException() {
        super("Invalid username or password");
    }

    public InvalidCredentialsException(String message) {
        super(message);
    }
}

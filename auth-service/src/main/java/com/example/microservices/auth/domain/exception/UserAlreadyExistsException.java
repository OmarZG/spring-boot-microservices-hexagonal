package com.example.microservices.auth.domain.exception;

/**
 * Exception thrown when user already exists
 */
public class UserAlreadyExistsException extends DomainException {

    public UserAlreadyExistsException(String message) {
        super(message);
    }

    public static UserAlreadyExistsException byUsername(String username) {
        return new UserAlreadyExistsException("User already exists with username: " + username);
    }

    public static UserAlreadyExistsException byEmail(String email) {
        return new UserAlreadyExistsException("User already exists with email: " + email);
    }
}

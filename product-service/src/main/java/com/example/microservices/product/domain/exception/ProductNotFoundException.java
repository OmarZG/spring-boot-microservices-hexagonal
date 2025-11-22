package com.example.microservices.product.domain.exception;

/**
 * Exception thrown when product is not found
 */
public class ProductNotFoundException extends RuntimeException {

    public ProductNotFoundException(String message) {
        super(message);
    }

    public static ProductNotFoundException byId(String id) {
        return new ProductNotFoundException("Product not found with id: " + id);
    }
}

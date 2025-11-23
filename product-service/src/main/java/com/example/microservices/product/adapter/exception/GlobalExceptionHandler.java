package com.example.microservices.product.adapter.exception;

import com.example.microservices.common.dto.ErrorResponse;
import com.example.microservices.common.exception.BaseGlobalExceptionHandler;
import com.example.microservices.product.domain.exception.ProductNotFoundException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.Instant;

/**
 * Global exception handler for product-service.
 * Extends {@link BaseGlobalExceptionHandler} to inherit common exception
 * handling
 * and adds product-service specific exception handlers.
 */
@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler extends BaseGlobalExceptionHandler {

        /**
         * Handle product not found exception
         */
        @ExceptionHandler(ProductNotFoundException.class)
        public ResponseEntity<ErrorResponse> handleProductNotFound(ProductNotFoundException ex) {
                log.error("Product not found: {}", ex.getMessage());

                ErrorResponse errorResponse = ErrorResponse.builder()
                                .errorCode("PRODUCT_NOT_FOUND")
                                .message(ex.getMessage())
                                .status(HttpStatus.NOT_FOUND.value())
                                .timestamp(Instant.now())
                                .build();

                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(errorResponse);
        }
}

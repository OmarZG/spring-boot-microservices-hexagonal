package com.example.microservices.product.application.dto;

import com.example.microservices.product.domain.enums.Category;
import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Size;

import java.math.BigDecimal;
import java.util.List;

/**
 * Update product request DTO using Java Record
 * All fields are optional for partial updates
 */
public record UpdateProductRequest(
        @Size(min = 3, max = 200, message = "Product name must be between 3 and 200 characters") String name,

        @Size(max = 2000, message = "Description must not exceed 2000 characters") String description,

        @DecimalMin(value = "0.01", message = "Price must be greater than 0") BigDecimal price,

        Category category,

        @Min(value = 0, message = "Stock cannot be negative") Integer stock,

        List<String> images) {
}

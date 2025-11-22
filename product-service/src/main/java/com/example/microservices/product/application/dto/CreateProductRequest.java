package com.example.microservices.product.application.dto;

import com.example.microservices.product.domain.enums.Category;
import jakarta.validation.constraints.*;

import java.math.BigDecimal;
import java.util.List;

/**
 * Create product request DTO using Java Record
 */
public record CreateProductRequest(
        @NotBlank(message = "Product name is required") @Size(min = 3, max = 200, message = "Product name must be between 3 and 200 characters") String name,

        @NotBlank(message = "Description is required") @Size(max = 2000, message = "Description must not exceed 2000 characters") String description,

        @NotNull(message = "Price is required") @DecimalMin(value = "0.01", message = "Price must be greater than 0") BigDecimal price,

        @NotNull(message = "Category is required") Category category,

        @NotNull(message = "Stock is required") @Min(value = 0, message = "Stock cannot be negative") Integer stock,

        List<String> images) {
}

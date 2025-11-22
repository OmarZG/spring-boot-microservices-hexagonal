package com.example.microservices.product.domain.model;

import com.example.microservices.product.domain.enums.Category;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.List;

/**
 * Pure domain entity for Product (framework-agnostic)
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Product {

    private String id;
    private String name;
    private String description;
    private BigDecimal price;
    private Category category;
    private Integer stock;
    private List<String> images;
    private List<Review> reviews;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

    /**
     * Business validation: Check if product is in stock
     */
    public boolean isInStock() {
        return stock != null && stock > 0;
    }

    /**
     * Business validation: Check if product is available
     */
    public boolean isAvailable() {
        return isInStock() && price != null && price.compareTo(BigDecimal.ZERO) > 0;
    }

    /**
     * Business logic: Reduce stock
     */
    public void reduceStock(int quantity) {
        if (stock == null || stock < quantity) {
            throw new IllegalStateException("Insufficient stock");
        }
        this.stock -= quantity;
    }

    /**
     * Business logic: Add stock
     */
    public void addStock(int quantity) {
        if (this.stock == null) {
            this.stock = quantity;
        } else {
            this.stock += quantity;
        }
    }

    /**
     * Nested class for product reviews
     */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Review {
        private String userId;
        private String username;
        private Integer rating;
        private String comment;
        private LocalDateTime createdAt;
    }
}

package com.example.microservices.product.application.dto;

import com.example.microservices.product.domain.enums.Category;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.List;

/**
 * Product DTO using Java Record
 */
public record ProductDTO(
        String id,
        String name,
        String description,
        BigDecimal price,
        Category category,
        Integer stock,
        List<String> images,
        List<ReviewDTO> reviews,
        LocalDateTime createdAt,
        LocalDateTime updatedAt) {
    public record ReviewDTO(
            String userId,
            String username,
            Integer rating,
            String comment,
            LocalDateTime createdAt) {
    }
}

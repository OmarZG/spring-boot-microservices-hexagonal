package com.example.microservices.product.infrastructure.adapter.persistence.document;

import com.example.microservices.product.domain.enums.Category;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.mongodb.core.mapping.Document;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.List;

/**
 * MongoDB document for Product
 */
@Document(collection = "products")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ProductDocument {

    @Id
    private String id;

    private String name;
    private String description;
    private BigDecimal price;
    private Category category;
    private Integer stock;
    private List<String> images;
    private List<ReviewDocument> reviews;

    @CreatedDate
    private LocalDateTime createdAt;

    @LastModifiedDate
    private LocalDateTime updatedAt;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ReviewDocument {
        private String userId;
        private String username;
        private Integer rating;
        private String comment;
        private LocalDateTime createdAt;
    }
}

package com.example.microservices.product.infrastructure.adapter.persistence;

import com.example.microservices.product.infrastructure.adapter.persistence.document.ProductDocument;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

/**
 * Spring Data MongoDB repository for ProductDocument
 */
@Repository
public interface ProductMongoRepository extends MongoRepository<ProductDocument, String> {
}

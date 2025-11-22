package com.example.microservices.product.infrastructure.adapter.persistence;

import com.example.microservices.product.application.mapper.ProductMapper;
import com.example.microservices.product.domain.model.Product;
import com.example.microservices.product.domain.port.out.ProductPort;
import com.example.microservices.product.infrastructure.adapter.persistence.document.ProductDocument;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Adapter that implements ProductPort using MongoDB repository
 */
@Component
@RequiredArgsConstructor
public class ProductPersistenceAdapter implements ProductPort {

    private final ProductMongoRepository mongoRepository;
    private final ProductMapper productMapper;

    @Override
    public Product save(Product product) {
        ProductDocument document = productMapper.toDocument(product);
        ProductDocument savedDocument = mongoRepository.save(document);
        return productMapper.toDomain(savedDocument);
    }

    @Override
    public Optional<Product> findById(String id) {
        return mongoRepository.findById(id)
                .map(productMapper::toDomain);
    }

    @Override
    public List<Product> findAll() {
        return mongoRepository.findAll().stream()
                .map(productMapper::toDomain)
                .collect(Collectors.toList());
    }

    @Override
    public void deleteById(String id) {
        mongoRepository.deleteById(id);
    }

    @Override
    public boolean existsById(String id) {
        return mongoRepository.existsById(id);
    }
}

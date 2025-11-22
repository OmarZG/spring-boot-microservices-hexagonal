package com.example.microservices.product.application.service;

import com.example.microservices.product.domain.exception.ProductNotFoundException;
import com.example.microservices.product.domain.model.Product;
import com.example.microservices.product.domain.port.in.ProductUseCase;
import com.example.microservices.product.domain.port.out.ProductPort;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * Product service implementation
 * Implements business logic for CRUD operations
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class ProductService implements ProductUseCase {

    private final ProductPort productPort;

    @Override
    public Product create(Product product) {
        log.info("Creating new product: {}", product.getName());
        Product savedProduct = productPort.save(product);
        log.info("Product created successfully with id: {}", savedProduct.getId());
        return savedProduct;
    }

    @Override
    public Product update(String id, Product product) {
        log.info("Updating product with id: {}", id);

        if (!productPort.existsById(id)) {
            throw ProductNotFoundException.byId(id);
        }

        product.setId(id);
        Product updatedProduct = productPort.save(product);
        log.info("Product updated successfully: {}", id);
        return updatedProduct;
    }

    @Override
    public void delete(String id) {
        log.info("Deleting product with id: {}", id);

        if (!productPort.existsById(id)) {
            throw ProductNotFoundException.byId(id);
        }

        productPort.deleteById(id);
        log.info("Product deleted successfully: {}", id);
    }

    @Override
    public Product findById(String id) {
        log.debug("Finding product by id: {}", id);
        return productPort.findById(id)
                .orElseThrow(() -> ProductNotFoundException.byId(id));
    }

    @Override
    public List<Product> findAll() {
        log.debug("Finding all products");
        return productPort.findAll();
    }
}

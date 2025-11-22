package com.example.microservices.product.domain.port.in;

import com.example.microservices.product.domain.model.Product;

import java.util.List;

/**
 * Input port for Product use cases
 */
public interface ProductUseCase {

    Product create(Product product);

    Product update(String id, Product product);

    void delete(String id);

    Product findById(String id);

    List<Product> findAll();
}

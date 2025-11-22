package com.example.microservices.product.domain.port.out;

import com.example.microservices.product.domain.model.Product;

import java.util.List;
import java.util.Optional;

/**
 * Output port for Product persistence operations
 */
public interface ProductPort {

    Product save(Product product);

    Optional<Product> findById(String id);

    List<Product> findAll();

    void deleteById(String id);

    boolean existsById(String id);
}

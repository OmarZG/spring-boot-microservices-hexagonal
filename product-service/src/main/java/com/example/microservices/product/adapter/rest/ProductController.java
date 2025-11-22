package com.example.microservices.product.adapter.rest;

import com.example.microservices.common.dto.ApiResponse;
import com.example.microservices.product.application.dto.CreateProductRequest;
import com.example.microservices.product.application.dto.ProductDTO;
import com.example.microservices.product.application.dto.UpdateProductRequest;
import com.example.microservices.product.application.mapper.ProductMapper;
import com.example.microservices.product.application.service.ProductService;
import com.example.microservices.product.domain.model.Product;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;

/**
 * REST Controller for product endpoints
 */
@Slf4j
@RestController
@RequestMapping("/api/products")
@RequiredArgsConstructor
public class ProductController {

    private final ProductService productService;
    private final ProductMapper productMapper;

    /**
     * Get all products
     */
    @GetMapping
    public ResponseEntity<ApiResponse<List<ProductDTO>>> getAllProducts() {
        log.info("Getting all products");

        List<Product> products = productService.findAll();
        List<ProductDTO> productDTOs = products.stream()
                .map(productMapper::toDTO)
                .collect(Collectors.toList());

        return ResponseEntity.ok(ApiResponse.success(productDTOs));
    }

    /**
     * Get product by ID
     */
    @GetMapping("/{id}")
    public ResponseEntity<ApiResponse<ProductDTO>> getProductById(@PathVariable String id) {
        log.info("Getting product by id: {}", id);

        Product product = productService.findById(id);
        ProductDTO productDTO = productMapper.toDTO(product);

        return ResponseEntity.ok(ApiResponse.success(productDTO));
    }

    /**
     * Create new product
     */
    @PostMapping
    public ResponseEntity<ApiResponse<ProductDTO>> createProduct(@Valid @RequestBody CreateProductRequest request) {
        log.info("Creating new product: {}", request.name());

        Product product = productMapper.toDomain(request);
        Product createdProduct = productService.create(product);
        ProductDTO productDTO = productMapper.toDTO(createdProduct);

        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(ApiResponse.success(productDTO, "Product created successfully"));
    }

    /**
     * Update existing product
     */
    @PutMapping("/{id}")
    public ResponseEntity<ApiResponse<ProductDTO>> updateProduct(
            @PathVariable String id,
            @Valid @RequestBody UpdateProductRequest request) {
        log.info("Updating product: {}", id);

        Product existingProduct = productService.findById(id);
        productMapper.updateDomainFromRequest(request, existingProduct);

        Product updatedProduct = productService.update(id, existingProduct);
        ProductDTO productDTO = productMapper.toDTO(updatedProduct);

        return ResponseEntity.ok(ApiResponse.success(productDTO, "Product updated successfully"));
    }

    /**
     * Delete product
     */
    @DeleteMapping("/{id}")
    public ResponseEntity<ApiResponse<Void>> deleteProduct(@PathVariable String id) {
        log.info("Deleting product: {}", id);

        productService.delete(id);

        return ResponseEntity.ok(ApiResponse.success(null, "Product deleted successfully"));
    }
}

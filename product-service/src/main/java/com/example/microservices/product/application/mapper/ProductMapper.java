package com.example.microservices.product.application.mapper;

import com.example.microservices.product.application.dto.CreateProductRequest;
import com.example.microservices.product.application.dto.ProductDTO;
import com.example.microservices.product.application.dto.UpdateProductRequest;
import com.example.microservices.product.domain.model.Product;
import com.example.microservices.product.infrastructure.adapter.persistence.document.ProductDocument;
import org.mapstruct.*;

/**
 * MapStruct mapper for Product conversions
 */
@Mapper(componentModel = MappingConstants.ComponentModel.SPRING, nullValuePropertyMappingStrategy = NullValuePropertyMappingStrategy.IGNORE)
public interface ProductMapper {

    ProductDTO toDTO(Product product);

    Product toDomain(ProductDTO dto);

    @Mapping(target = "id", ignore = true)
    @Mapping(target = "reviews", ignore = true)
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "updatedAt", ignore = true)
    Product toDomain(CreateProductRequest request);

    @Mapping(target = "id", ignore = true)
    @Mapping(target = "reviews", ignore = true)
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "updatedAt", ignore = true)
    @BeanMapping(nullValuePropertyMappingStrategy = NullValuePropertyMappingStrategy.IGNORE)
    void updateDomainFromRequest(UpdateProductRequest request, @MappingTarget Product product);

    ProductDocument toDocument(Product product);

    Product toDomain(ProductDocument document);
}

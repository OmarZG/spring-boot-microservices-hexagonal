package com.example.microservices.auth.application.mapper;

import com.example.microservices.auth.application.dto.RegisterRequest;
import com.example.microservices.auth.application.dto.UserDTO;
import com.example.microservices.auth.domain.model.User;
import com.example.microservices.auth.infrastructure.adapter.persistence.entity.UserEntity;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.MappingConstants;

/**
 * MapStruct mapper for User conversions
 */
@Mapper(componentModel = MappingConstants.ComponentModel.SPRING)
public interface UserMapper {

    /**
     * Convert domain User to UserDTO
     */
    UserDTO toDTO(User user);

    /**
     * Convert UserDTO to domain User
     */
    User toDomain(UserDTO dto);

    /**
     * Convert RegisterRequest to domain User
     */
    @Mapping(target = "id", ignore = true)
    @Mapping(target = "password", ignore = true) // Password handled separately
    @Mapping(target = "enabled", constant = "true")
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "updatedAt", ignore = true)
    User toDomain(RegisterRequest request);

    /**
     * Convert domain User to UserEntity (JPA)
     */
    UserEntity toEntity(User user);

    /**
     * Convert UserEntity (JPA) to domain User
     */
    User toDomain(UserEntity entity);
}

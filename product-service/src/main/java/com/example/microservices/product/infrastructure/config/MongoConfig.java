package com.example.microservices.product.infrastructure.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.data.mongodb.config.EnableMongoAuditing;
import org.springframework.data.mongodb.repository.config.EnableMongoRepositories;

/**
 * MongoDB configuration
 */
@Configuration
@EnableMongoRepositories(basePackages = "com.example.microservices.product.infrastructure.adapter.persistence")
@EnableMongoAuditing
public class MongoConfig {
}

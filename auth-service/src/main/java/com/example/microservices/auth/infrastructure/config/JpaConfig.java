package com.example.microservices.auth.infrastructure.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.transaction.annotation.EnableTransactionManagement;

/**
 * JPA configuration
 */
@Configuration
@EnableJpaRepositories(basePackages = "com.example.microservices.auth.infrastructure.adapter.persistence")
@EnableJpaAuditing
@EnableTransactionManagement
public class JpaConfig {
}

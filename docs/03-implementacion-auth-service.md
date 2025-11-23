# Implementación del Auth Service: Autenticación con JWT y RSA

> **Serie: Construyendo Microservicios con Spring Boot y Arquitectura Hexagonal**  
> Parte 3 de 7 - Auth Service con PostgreSQL y JWT

## 📖 Introducción

En este artículo implementaremos completamente el **auth-service**, nuestro microservicio de autenticación. Aplicaremos los principios de arquitectura hexagonal que vimos en la Parte 1, usando la estructura del proyecto configurada en la Parte 2.

**Características que implementaremos:**
- 🔐 Registro y login de usuarios
- 🔑 JWT firmado con RSA 2048-bit
- 👥 Sistema de roles y permisos granulares
- 🛡️ Spring Security con autenticación stateless
- 📊 PostgreSQL con JPA

## 🏗️ Arquitectura del Auth Service

```mermaid
graph TB
    subgraph "Adapter Layer - REST"
        CTRL[AuthController]
    end
    
    subgraph "Application Layer"
        UC[AuthService<br/>UseCase Implementation]
        MAPPER[UserMapper<br/>MapStruct]
        DTO[DTOs]
    end
    
    subgraph "Domain Layer"
        USER[User Entity]
        ROLE[Role Enum]
        PORT_IN[AuthUseCase<br/>Port In]
        PORT_OUT[UserPort<br/>Port Out]
    end
    
    subgraph "Infrastructure Layer"
        JPA_ADAPTER[UserJpaAdapter]
        JWT[JwtTokenProvider]
        SEC[SecurityConfig]
        ENTITY[UserEntity<br/>JPA]
    end
    
    subgraph "Database"
        PG[(PostgreSQL)]
    end
    
    CTRL --> UC
    UC --> PORT_IN
    UC --> PORT_OUT
    UC --> MAPPER
    PORT_OUT --> JPA_ADAPTER
    JPA_ADAPTER --> ENTITY
    ENTITY --> PG
    UC --> JWT
    
    style USER fill:#4A90E2,color:#fff
    style ROLE fill:#4A90E2,color:#fff
    style PORT_IN fill:#4A90E2,color:#fff
    style PORT_OUT fill:#4A90E2,color:#fff
```

## 📦 Paso 1: Capa de Dominio

### 1.1 Role Enum - Roles y Permisos

```java
package com.example.microservices.auth.domain.enums;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Roles del sistema con permisos granulares
 */
public enum Role {
    USER(Set.of(
            "product:read")),
    
    MODERATOR(Set.of(
            "user:read",
            "user:update",
            "user:moderate",
            "product:read",
            "product:create",
            "product:update")),
    
    ADMIN(Set.of(
            "user:read",
            "user:create",
            "user:update",
            "user:delete",
            "product:read",
            "product:create",
            "product:update",
            "product:delete",
            "admin:all"));

    private final Set<String> permissions;

    Role(Set<String> permissions) {
        this.permissions = permissions;
    }

    public Set<String> getPermissions() {
        return permissions;
    }

    /**
     * Convierte el rol y sus permisos a GrantedAuthority de Spring Security
     */
    public Collection<? extends GrantedAuthority> getAuthorities() {
        List<GrantedAuthority> authorities = permissions.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        // Agregar el rol con prefijo ROLE_
        authorities.add(new SimpleGrantedAuthority("ROLE_" + this.name()));

        return authorities;
    }
}
```

**Explicación:**
- Cada rol tiene permisos específicos (ej: `product:read`)
- `getAuthorities()` convierte a formato Spring Security
- Se agrega `ROLE_` prefix automáticamente

### 1.2 User Entity - Modelo de Dominio

```java
package com.example.microservices.auth.domain.model;

import com.example.microservices.auth.domain.enums.Role;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.Set;

/**
 * Entidad de dominio User - Sin anotaciones de JPA
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class User {
    private Long id;
    private String username;
    private String email;
    private String password;
    private Set<Role> roles;
    private boolean enabled;
    private Instant createdAt;
    private Instant updatedAt;

    // Constructor para creación
    public User(String username, String email, String password, Set<Role> roles) {
        this.username = username;
        this.email = email;
        this.password = password;
        this.roles = roles;
        this.enabled = false;
        this.createdAt = Instant.now();
    }

    /**
     * Regla de negocio: Activar usuario
     */
    public void activate() {
        if (this.email == null || this.email.isEmpty()) {
            throw new IllegalStateException("Cannot activate user without email");
        }
        this.enabled = true;
    }

    /**
     * Regla de negocio: Verificar si tiene un permiso específico
     */
    public boolean hasPermission(String permission) {
        return roles.stream()
                .flatMap(role -> role.getPermissions().stream())
                .anyMatch(p -> p.equals(permission));
    }
}
```

> [!IMPORTANT]
> **Dominio Puro**: La entidad `User` no tiene anotaciones de JPA. Es código Java puro que representa el negocio.

### 1.3 Puertos (Interfaces)

#### Puerto de Entrada - Casos de Uso

```java
package com.example.microservices.auth.domain.port.in;

import com.example.microservices.auth.domain.model.User;

/**
 * Puerto de entrada - Define los casos de uso de autenticación
 */
public interface AuthUseCase {
    /**
     * Registrar un nuevo usuario
     */
    User register(User user, String rawPassword);

    /**
     * Autenticar usuario y generar token
     */
    String login(String username, String password);

    /**
     * Validar token JWT
     */
    boolean validateToken(String token);

    /**
     * Obtener username desde token
     */
    String getUsernameFromToken(String token);

    /**
     * Obtener usuario actual autenticado
     */
    User getCurrentUser();
}
```

#### Puerto de Salida - Persistencia

```java
package com.example.microservices.auth.domain.port.out;

import com.example.microservices.auth.domain.model.User;

import java.util.Optional;

/**
 * Puerto de salida - Define operaciones de persistencia
 */
public interface UserPort {
    User save(User user);
    Optional<User> findById(Long id);
    Optional<User> findByUsername(String username);
    Optional<User> findByEmail(String email);
    boolean existsByUsername(String username);
    boolean existsByEmail(String email);
    void deleteById(Long id);
}
```

### 1.4 Excepciones de Dominio

```java
package com.example.microservices.auth.domain.exception;

/**
 * Excepción cuando el usuario ya existe
 */
public class UserAlreadyExistsException extends RuntimeException {
    public UserAlreadyExistsException(String message) {
        super(message);
    }

    public static UserAlreadyExistsException byUsername(String username) {
        return new UserAlreadyExistsException(
            "User already exists with username: " + username
        );
    }

    public static UserAlreadyExistsException byEmail(String email) {
        return new UserAlreadyExistsException(
            "User already exists with email: " + email
        );
    }
}
```

```java
package com.example.microservices.auth.domain.exception;

public class InvalidCredentialsException extends RuntimeException {
    public InvalidCredentialsException() {
        super("Invalid username or password");
    }

    public InvalidCredentialsException(String message) {
        super(message);
    }
}
```

## 🎯 Paso 2: Capa de Aplicación

### 2.1 DTOs

```java
package com.example.microservices.auth.application.dto;

import com.example.microservices.auth.domain.enums.Role;

import java.util.Set;

/**
 * DTO para registro de usuario
 */
public record RegisterRequest(
    String username,
    String email,
    String password,
    Set<Role> roles
) {}
```

```java
package com.example.microservices.auth.application.dto;

/**
 * DTO para login
 */
public record LoginRequest(
    String username,
    String password
) {}
```

```java
package com.example.microservices.auth.application.dto;

import com.example.microservices.auth.domain.enums.Role;

import java.util.Set;

/**
 * DTO de respuesta de usuario
 */
public record UserDTO(
    Long id,
    String username,
    String email,
    Set<Role> roles,
    boolean enabled
) {}
```

```java
package com.example.microservices.auth.application.dto;

/**
 * DTO de respuesta de login
 */
public record LoginResponse(
    String token,
    String type,
    Long expiresIn,
    UserDTO user
) {
    public LoginResponse(String token, Long expiresIn, UserDTO user) {
        this(token, "Bearer", expiresIn, user);
    }
}
```

### 2.2 Mapper con MapStruct

```java
package com.example.microservices.auth.application.mapper;

import com.example.microservices.auth.application.dto.RegisterRequest;
import com.example.microservices.auth.application.dto.UserDTO;
import com.example.microservices.auth.domain.model.User;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

/**
 * Mapper entre User (dominio) y DTOs
 */
@Mapper(componentModel = "spring")
public interface UserMapper {
    
    UserDTO toDTO(User user);

    @Mapping(target = "id", ignore = true)
    @Mapping(target = "password", ignore = true)
    @Mapping(target = "enabled", ignore = true)
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "updatedAt", ignore = true)
    User toDomain(RegisterRequest request);
}
```

### 2.3 AuthService - Implementación del Caso de Uso

```java
package com.example.microservices.auth.application.service;

import com.example.microservices.auth.domain.exception.InvalidCredentialsException;
import com.example.microservices.auth.domain.exception.UserAlreadyExistsException;
import com.example.microservices.auth.domain.exception.UserNotFoundException;
import com.example.microservices.auth.domain.model.User;
import com.example.microservices.auth.domain.port.in.AuthUseCase;
import com.example.microservices.auth.domain.port.out.UserPort;
import com.example.microservices.auth.infrastructure.adapter.security.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Implementación de los casos de uso de autenticación
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService implements AuthUseCase {

    private final UserPort userPort;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final AuthenticationManager authenticationManager;

    @Override
    @Transactional
    public User register(User user, String rawPassword) {
        log.info("Registering new user: {}", user.getUsername());

        // Validar que no exista el username
        if (userPort.existsByUsername(user.getUsername())) {
            throw UserAlreadyExistsException.byUsername(user.getUsername());
        }

        // Validar que no exista el email
        if (userPort.existsByEmail(user.getEmail())) {
            throw UserAlreadyExistsException.byEmail(user.getEmail());
        }

        // Encriptar contraseña
        user.setPassword(passwordEncoder.encode(rawPassword));
        user.setEnabled(true);

        // Guardar usuario
        User savedUser = userPort.save(user);
        log.info("User registered successfully: {}", savedUser.getUsername());

        return savedUser;
    }

    @Override
    public String login(String username, String password) {
        log.info("Attempting login for user: {}", username);

        try {
            // Autenticar con Spring Security
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password));

            SecurityContextHolder.getContext().setAuthentication(authentication);

            // Generar JWT
            String token = jwtTokenProvider.generateToken(authentication);
            log.info("User logged in successfully: {}", username);

            return token;
        } catch (Exception e) {
            log.error("Login failed for user: {}", username, e);
            throw new InvalidCredentialsException();
        }
    }

    @Override
    public boolean validateToken(String token) {
        return jwtTokenProvider.validateToken(token);
    }

    @Override
    public String getUsernameFromToken(String token) {
        return jwtTokenProvider.getUsernameFromToken(token);
    }

    @Override
    public User getCurrentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()) {
            throw new InvalidCredentialsException("No authenticated user found");
        }

        String username = authentication.getName();
        return userPort.findByUsername(username)
                .orElseThrow(() -> new UserNotFoundException("username", username));
    }

    public Long getExpirationTime() {
        return jwtTokenProvider.getExpirationTime();
    }
}
```

## 🔧 Paso 3: Capa de Infraestructura

### 3.1 Entidad JPA

```java
package com.example.microservices.auth.infrastructure.adapter.persistence.entity;

import com.example.microservices.auth.domain.enums.Role;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.Instant;
import java.util.Set;

/**
 * Entidad JPA para persistencia
 */
@Entity
@Table(name = "users")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserEntity {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false, length = 50)
    private String username;

    @Column(unique = true, nullable = false, length = 100)
    private String email;

    @Column(nullable = false)
    private String password;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "user_roles", joinColumns = @JoinColumn(name = "user_id"))
    @Enumerated(EnumType.STRING)
    @Column(name = "role")
    private Set<Role> roles;

    @Column(nullable = false)
    private boolean enabled = true;

    @CreationTimestamp
    @Column(nullable = false, updatable = false)
    private Instant createdAt;

    @UpdateTimestamp
    private Instant updatedAt;
}
```

### 3.2 JPA Repository

```java
package com.example.microservices.auth.infrastructure.adapter.persistence;

import com.example.microservices.auth.infrastructure.adapter.persistence.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserJpaRepository extends JpaRepository<UserEntity, Long> {
    Optional<UserEntity> findByUsername(String username);
    Optional<UserEntity> findByEmail(String email);
    boolean existsByUsername(String username);
    boolean existsByEmail(String email);
}
```

### 3.3 Adaptador JPA - Implementa UserPort

```java
package com.example.microservices.auth.infrastructure.adapter.persistence;

import com.example.microservices.auth.domain.model.User;
import com.example.microservices.auth.domain.port.out.UserPort;
import com.example.microservices.auth.infrastructure.adapter.persistence.entity.UserEntity;
import com.example.microservices.auth.infrastructure.adapter.persistence.mapper.UserEntityMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.Optional;

/**
 * Adaptador que implementa UserPort usando JPA
 */
@Component
@RequiredArgsConstructor
public class UserJpaAdapter implements UserPort {

    private final UserJpaRepository jpaRepository;
    private final UserEntityMapper mapper;

    @Override
    public User save(User user) {
        UserEntity entity = mapper.toEntity(user);
        UserEntity saved = jpaRepository.save(entity);
        return mapper.toDomain(saved);
    }

    @Override
    public Optional<User> findById(Long id) {
        return jpaRepository.findById(id)
                .map(mapper::toDomain);
    }

    @Override
    public Optional<User> findByUsername(String username) {
        return jpaRepository.findByUsername(username)
                .map(mapper::toDomain);
    }

    @Override
    public Optional<User> findByEmail(String email) {
        return jpaRepository.findByEmail(email)
                .map(mapper::toDomain);
    }

    @Override
    public boolean existsByUsername(String username) {
        return jpaRepository.existsByUsername(username);
    }

    @Override
    public boolean existsByEmail(String email) {
        return jpaRepository.existsByEmail(email);
    }

    @Override
    public void deleteById(Long id) {
        jpaRepository.deleteById(id);
    }
}
```

### 3.4 JWT Token Provider

```java
package com.example.microservices.auth.infrastructure.adapter.security;

import com.example.microservices.common.security.RsaKeyUtils;
import io.jsonwebtoken.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;
import java.util.stream.Collectors;

/**
 * Proveedor de tokens JWT con firma RSA
 */
@Slf4j
@Component
public class JwtTokenProvider {

    @Value("${jwt.expiration}")
    private Long jwtExpiration;

    @Value("${jwt.issuer}")
    private String jwtIssuer;

    @Value("classpath:${jwt.private-key-path}")
    private Resource privateKeyResource;

    @Value("classpath:${jwt.public-key-path}")
    private Resource publicKeyResource;

    private PrivateKey privateKey;
    private PublicKey publicKey;

    /**
     * Generar token JWT desde Authentication
     */
    public String generateToken(Authentication authentication) {
        try {
            if (privateKey == null) {
                loadKeys();
            }

            String username = authentication.getName();
            Date now = new Date();
            Date expiryDate = new Date(now.getTime() + jwtExpiration);

            // Extraer roles y permisos
            String roles = authentication.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.joining(","));

            return Jwts.builder()
                    .subject(username)
                    .issuedAt(now)
                    .expiration(expiryDate)
                    .issuer(jwtIssuer)
                    .claim("roles", roles)
                    .signWith(privateKey, Jwts.SIG.RS256)
                    .compact();
        } catch (Exception e) {
            log.error("Error generating JWT token", e);
            throw new RuntimeException("Error generating JWT token", e);
        }
    }

    /**
     * Validar token JWT
     */
    public boolean validateToken(String token) {
        try {
            if (publicKey == null) {
                loadKeys();
            }

            Jwts.parser()
                    .verifyWith(publicKey)
                    .build()
                    .parseSignedClaims(token);

            return true;
        } catch (SecurityException ex) {
            log.error("Invalid JWT signature");
        } catch (MalformedJwtException ex) {
            log.error("Invalid JWT token");
        } catch (ExpiredJwtException ex) {
            log.error("Expired JWT token");
        } catch (UnsupportedJwtException ex) {
            log.error("Unsupported JWT token");
        } catch (IllegalArgumentException ex) {
            log.error("JWT claims string is empty");
        } catch (Exception ex) {
            log.error("JWT validation error", ex);
        }
        return false;
    }

    /**
     * Obtener username del token
     */
    public String getUsernameFromToken(String token) {
        try {
            if (publicKey == null) {
                loadKeys();
            }

            Claims claims = Jwts.parser()
                    .verifyWith(publicKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            return claims.getSubject();
        } catch (Exception e) {
            log.error("Error extracting username from token", e);
            return null;
        }
    }

    public Long getExpirationTime() {
        return jwtExpiration / 1000; // Convertir a segundos
    }

    private void loadKeys() throws Exception {
        this.privateKey = RsaKeyUtils.loadPrivateKey(privateKeyResource);
        this.publicKey = RsaKeyUtils.loadPublicKey(publicKeyResource);
        log.info("RSA keys loaded successfully");
    }
}
```

### 3.5 Spring Security Configuration

```java
package com.example.microservices.auth.infrastructure.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Configuración de Spring Security
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/auth/register", "/api/auth/login").permitAll()
                        .requestMatchers("/actuator/**").permitAll()
                        .anyRequest().authenticated())
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }
}
```

## 🌐 Paso 4: Capa de Adaptadores (REST)

### 4.1 AuthController

```java
package com.example.microservices.auth.adapter.rest;

import com.example.microservices.auth.application.dto.*;
import com.example.microservices.auth.application.mapper.UserMapper;
import com.example.microservices.auth.application.service.AuthService;
import com.example.microservices.auth.domain.model.User;
import com.example.microservices.common.dto.ApiResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * Controlador REST para autenticación
 */
@Slf4j
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final UserMapper userMapper;

    @PostMapping("/register")
    public ResponseEntity<ApiResponse<UserDTO>> register(
            @Valid @RequestBody RegisterRequest request) {
        log.info("Register request for username: {}", request.username());

        User user = userMapper.toDomain(request);
        User registered = authService.register(user, request.password());

        return ResponseEntity.ok(
                ApiResponse.success(userMapper.toDTO(registered), "User registered successfully")
        );
    }

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<LoginResponse>> login(
            @Valid @RequestBody LoginRequest request) {
        log.info("Login request for username: {}", request.username());

        String token = authService.login(request.username(), request.password());
        User user = authService.getCurrentUser();

        LoginResponse response = new LoginResponse(
                token,
                authService.getExpirationTime(),
                userMapper.toDTO(user)
        );

        return ResponseEntity.ok(
                ApiResponse.success(response, "Login successful")
        );
    }

    @GetMapping("/me")
    public ResponseEntity<ApiResponse<UserDTO>> getCurrentUser() {
        User user = authService.getCurrentUser();
        return ResponseEntity.ok(
                ApiResponse.success(userMapper.toDTO(user))
        );
    }
}
```

## 🔑 Paso 5: Generar Claves RSA

Crear utilidad para generar claves:

```java
package com.example.microservices.auth.infrastructure.util;

import java.io.FileWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

/**
 * Generador de claves RSA
 */
public class KeyGenerator {
    
    public static void main(String[] args) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair pair = keyGen.generateKeyPair();
        
        PrivateKey privateKey = pair.getPrivate();
        PublicKey publicKey = pair.getPublic();
        
        // Guardar clave privada
        try (FileWriter fw = new FileWriter("src/main/resources/certs/private_key.pem")) {
            fw.write("-----BEGIN PRIVATE KEY-----\n");
            fw.write(Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(privateKey.getEncoded()));
            fw.write("\n-----END PRIVATE KEY-----\n");
        }
        
        // Guardar clave pública
        try (FileWriter fw = new FileWriter("src/main/resources/certs/public_key.pem")) {
            fw.write("-----BEGIN PUBLIC KEY-----\n");
            fw.write(Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(publicKey.getEncoded()));
            fw.write("\n-----END PUBLIC KEY-----\n");
        }
        
        System.out.println("✅ RSA keys generated successfully!");
    }
}
```

**Ejecutar:**

```bash
cd auth-service
mvn compile exec:java -Dexec.mainClass="com.example.microservices.auth.infrastructure.util.KeyGenerator"
```

## ✅ Probar el Auth Service

### 1. Iniciar el servicio

```bash
cd auth-service
mvn spring-boot:run
```

### 2. Registrar usuario

```bash
curl -X POST http://localhost:8081/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "email": "admin@example.com",
    "password": "Admin123!",
    "roles": ["ADMIN"]
  }'
```

### 3. Login

```bash
curl -X POST http://localhost:8081/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "Admin123!"
  }'
```

**Respuesta:**

```json
{
  "code": "SUCCESS",
  "message": "Login successful",
  "data": {
    "token": "eyJhbGciOiJSUzI1NiJ9...",
    "type": "Bearer",
    "expiresIn": 86400,
    "user": {
      "id": 1,
      "username": "admin",
      "email": "admin@example.com",
      "roles": ["ADMIN"],
      "enabled": true
    }
  },
  "timestamp": "2025-11-23T10:00:00Z"
}
```

## 📊 Flujo Completo

```mermaid
sequenceDiagram
    participant C as Client
    participant CTRL as AuthController
    participant UC as AuthService
    participant PORT as UserPort
    participant JPA as UserJpaAdapter
    participant DB as PostgreSQL
    participant JWT as JwtTokenProvider

    C->>CTRL: POST /api/auth/register
    CTRL->>UC: register(user, password)
    UC->>PORT: existsByUsername()
    PORT->>JPA: existsByUsername()
    JPA->>DB: SELECT
    DB-->>JPA: false
    JPA-->>PORT: false
    PORT-->>UC: false
    UC->>UC: encode password
    UC->>PORT: save(user)
    PORT->>JPA: save(userEntity)
    JPA->>DB: INSERT
    DB-->>JPA: userEntity
    JPA-->>PORT: user
    PORT-->>UC: user
    UC-->>CTRL: user
    CTRL-->>C: 200 OK + UserDTO

    C->>CTRL: POST /api/auth/login
    CTRL->>UC: login(username, password)
    UC->>UC: authenticate()
    UC->>JWT: generateToken()
    JWT-->>UC: token
    UC-->>CTRL: token
    CTRL-->>C: 200 OK + LoginResponse
```

## 🎯 Puntos Clave Implementados

✅ **Arquitectura Hexagonal**
- Dominio puro sin dependencias de frameworks
- Puertos (interfaces) bien definidos
- Adaptadores intercambiables

✅ **Seguridad**
- JWT firmado con RSA 2048-bit
- Contraseñas con BCrypt
- Roles y permisos granulares

✅ **Mejores Prácticas**
- DTOs con Java Records
- MapStruct para mapeo
- Transacciones con `@Transactional`
- Logging estructurado

## 📚 Próximo Artículo

En **Parte 4: Implementación del Product Service**, veremos:
- MongoDB con Spring Data
- Validación de JWT (solo clave pública)
- CRUD completo de productos
- Autorización basada en permisos

---

**Serie Completa:**
1. Introducción a la Arquitectura Hexagonal
2. Setup del Proyecto Multi-Módulo
3. **Implementación del Auth Service** ← Estás aquí
4. Implementación del Product Service
5. Seguridad con JWT y RSA
6. Patrones y Mejores Prácticas
7. Testing y Deployment

# Setup del Proyecto: Microservicios con Maven Multi-Módulo

> **Serie: Construyendo Microservicios con Spring Boot y Arquitectura Hexagonal**  
> Parte 2 de 7 - Configuración del Proyecto Multi-Módulo

## 📖 Introducción

En el artículo anterior exploramos los conceptos de la arquitectura hexagonal. Ahora es momento de poner manos a la obra y configurar la estructura completa de nuestro proyecto de microservicios.

Construiremos:
- 🏗️ Proyecto Maven multi-módulo
- 🔐 **auth-service**: Autenticación con PostgreSQL
- 📦 **product-service**: Catálogo con MongoDB
- 🔧 **common**: Módulo compartido
- 🐳 Docker Compose para infraestructura

## 🎯 Arquitectura del Sistema

```mermaid
graph TB
    subgraph "Client Layer"
        POSTMAN[Postman/Client]
    end
    
    subgraph "Microservices"
        AUTH[Auth Service<br/>:8081<br/>PostgreSQL]
        PRODUCT[Product Service<br/>:8082<br/>MongoDB]
    end
    
    subgraph "Infrastructure"
        PG[(PostgreSQL<br/>:5432)]
        MONGO[(MongoDB<br/>:27017)]
        PGADMIN[pgAdmin<br/>:5050]
        MONGOEX[Mongo Express<br/>:8081]
    end
    
    POSTMAN -->|Register/Login| AUTH
    POSTMAN -->|JWT Token| PRODUCT
    AUTH --> PG
    PRODUCT --> MONGO
    PGADMIN -.->|Manage| PG
    MONGOEX -.->|Manage| MONGO
    
    style AUTH fill:#4A90E2,color:#fff
    style PRODUCT fill:#50C878,color:#fff
```

## 📦 Estructura del Proyecto

```
microservices-hexagonal/
├── pom.xml                           # Parent POM
├── common/                           # Módulo compartido
│   ├── pom.xml
│   └── src/main/java/
│       └── com/example/microservices/common/
│           ├── dto/
│           │   ├── ApiResponse.java
│           │   └── ErrorResponse.java
│           └── security/
│               └── RsaKeyUtils.java
│
├── auth-service/                     # Servicio de autenticación
│   ├── pom.xml
│   └── src/main/
│       ├── java/com/example/microservices/auth/
│       │   ├── domain/              # Núcleo del negocio
│       │   ├── application/         # Casos de uso
│       │   ├── infrastructure/      # Adaptadores técnicos
│       │   └── adapter/             # Controladores REST
│       └── resources/
│           ├── application.yml
│           ├── application-dev.yml
│           └── certs/               # Claves RSA (gitignored)
│
├── product-service/                  # Servicio de productos
│   ├── pom.xml
│   └── src/main/
│       ├── java/com/example/microservices/product/
│       │   ├── domain/
│       │   ├── application/
│       │   ├── infrastructure/
│       │   └── adapter/
│       └── resources/
│           ├── application.yml
│           ├── application-dev.yml
│           └── certs/               # Clave pública RSA
│
├── docker-compose.yml                # Infraestructura
├── .gitignore
└── README.md
```

## 🔧 Paso 1: Parent POM

El POM padre define las versiones y dependencias comunes:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 
         http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>3.5.8</version>
        <relativePath/>
    </parent>

    <groupId>com.example.microservices</groupId>
    <artifactId>microservices-hexagonal</artifactId>
    <version>1.0.0</version>
    <packaging>pom</packaging>

    <name>Microservices Hexagonal Architecture</name>
    <description>Multi-module microservices with hexagonal architecture</description>

    <!-- Módulos del proyecto -->
    <modules>
        <module>common</module>
        <module>auth-service</module>
        <module>product-service</module>
    </modules>

    <properties>
        <java.version>21</java.version>
        <maven.compiler.source>21</maven.compiler.source>
        <maven.compiler.target>21</maven.compiler.target>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
        
        <!-- Versiones de dependencias -->
        <mapstruct.version>1.6.3</mapstruct.version>
        <lombok.version>1.18.36</lombok.version>
        <jjwt.version>0.12.6</jjwt.version>
    </properties>

    <!-- Gestión centralizada de versiones -->
    <dependencyManagement>
        <dependencies>
            <!-- Módulo común -->
            <dependency>
                <groupId>com.example.microservices</groupId>
                <artifactId>common</artifactId>
                <version>${project.version}</version>
            </dependency>

            <!-- MapStruct -->
            <dependency>
                <groupId>org.mapstruct</groupId>
                <artifactId>mapstruct</artifactId>
                <version>${mapstruct.version}</version>
            </dependency>

            <!-- JWT -->
            <dependency>
                <groupId>io.jsonwebtoken</groupId>
                <artifactId>jjwt-api</artifactId>
                <version>${jjwt.version}</version>
            </dependency>
            <dependency>
                <groupId>io.jsonwebtoken</groupId>
                <artifactId>jjwt-impl</artifactId>
                <version>${jjwt.version}</version>
            </dependency>
            <dependency>
                <groupId>io.jsonwebtoken</groupId>
                <artifactId>jjwt-jackson</artifactId>
                <version>${jjwt.version}</version>
            </dependency>
        </dependencies>
    </dependencyManagement>

    <build>
        <pluginManagement>
            <plugins>
                <!-- Compiler plugin con MapStruct -->
                <plugin>
                    <groupId>org.apache.maven.plugins</groupId>
                    <artifactId>maven-compiler-plugin</artifactId>
                    <version>3.13.0</version>
                    <configuration>
                        <source>21</source>
                        <target>21</target>
                        <annotationProcessorPaths>
                            <path>
                                <groupId>org.mapstruct</groupId>
                                <artifactId>mapstruct-processor</artifactId>
                                <version>${mapstruct.version}</version>
                            </path>
                            <path>
                                <groupId>org.projectlombok</groupId>
                                <artifactId>lombok</artifactId>
                                <version>${lombok.version}</version>
                            </path>
                            <path>
                                <groupId>org.projectlombok</groupId>
                                <artifactId>lombok-mapstruct-binding</artifactId>
                                <version>0.2.0</version>
                            </path>
                        </annotationProcessorPaths>
                    </configuration>
                </plugin>
            </plugins>
        </pluginManagement>
    </build>
</project>
```

### 🔑 Puntos Clave del Parent POM:

1. **Spring Boot 3.5.8** como parent
2. **Java 21** configurado
3. **Módulos**: common, auth-service, product-service
4. **Versiones centralizadas** en `<properties>`
5. **Annotation processors** para MapStruct y Lombok

## 📚 Paso 2: Módulo Common

El módulo `common` contiene código compartido entre servicios:

### common/pom.xml

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 
         http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <parent>
        <groupId>com.example.microservices</groupId>
        <artifactId>microservices-hexagonal</artifactId>
        <version>1.0.0</version>
    </parent>

    <artifactId>common</artifactId>
    <packaging>jar</packaging>
    <name>Common Module</name>

    <dependencies>
        <!-- Solo dependencias necesarias para DTOs y utilidades -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter</artifactId>
        </dependency>
        
        <dependency>
            <groupId>org.projectlombok</groupId>
            <artifactId>lombok</artifactId>
            <optional>true</optional>
        </dependency>

        <!-- Para RsaKeyUtils -->
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-core</artifactId>
        </dependency>
    </dependencies>
</project>
```

### ApiResponse.java - Respuesta Estándar

```java
package com.example.microservices.common.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

/**
 * Respuesta estándar para todas las APIs
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class ApiResponse<T> {
    private String code;
    private String message;
    private T data;
    private Instant timestamp;

    public static <T> ApiResponse<T> success(T data) {
        return new ApiResponse<>(
            "SUCCESS",
            "Request processed successfully",
            data,
            Instant.now()
        );
    }

    public static <T> ApiResponse<T> success(T data, String message) {
        return new ApiResponse<>(
            "SUCCESS",
            message,
            data,
            Instant.now()
        );
    }
}
```

### ErrorResponse.java - Respuesta de Error

```java
package com.example.microservices.common.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.List;

/**
 * Respuesta de error estándar
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class ErrorResponse {
    private String errorCode;
    private String message;
    private int status;
    private Instant timestamp;
    private List<FieldError> fieldErrors;

    public ErrorResponse(String errorCode, String message, int status) {
        this.errorCode = errorCode;
        this.message = message;
        this.status = status;
        this.timestamp = Instant.now();
    }

    @Data
    @AllArgsConstructor
    public static class FieldError {
        private String field;
        private String message;
        private Object rejectedValue;
    }
}
```

## 🐳 Paso 3: Docker Compose

Configuramos la infraestructura con Docker:

### docker-compose.yml

```yaml
version: '3.8'

services:
  # PostgreSQL para auth-service
  postgres:
    image: postgres:16-alpine
    container_name: microservices-postgres
    environment:
      POSTGRES_DB: authdb
      POSTGRES_USER: admin
      POSTGRES_PASSWORD: admin123
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
    networks:
      - microservices-network

  # pgAdmin para gestionar PostgreSQL
  pgadmin:
    image: dpage/pgadmin4:latest
    container_name: microservices-pgadmin
    environment:
      PGADMIN_DEFAULT_EMAIL: admin@admin.com
      PGADMIN_DEFAULT_PASSWORD: admin
    ports:
      - "5050:80"
    depends_on:
      - postgres
    networks:
      - microservices-network

  # MongoDB para product-service
  mongodb:
    image: mongo:7
    container_name: microservices-mongodb
    environment:
      MONGO_INITDB_ROOT_USERNAME: admin
      MONGO_INITDB_ROOT_PASSWORD: admin123
      MONGO_INITDB_DATABASE: productdb
    ports:
      - "27017:27017"
    volumes:
      - mongodb_data:/data/db
    networks:
      - microservices-network

  # Mongo Express para gestionar MongoDB
  mongo-express:
    image: mongo-express:latest
    container_name: microservices-mongo-express
    environment:
      ME_CONFIG_MONGODB_ADMINUSERNAME: admin
      ME_CONFIG_MONGODB_ADMINPASSWORD: admin123
      ME_CONFIG_MONGODB_URL: mongodb://admin:admin123@mongodb:27017/
      ME_CONFIG_BASICAUTH_USERNAME: admin
      ME_CONFIG_BASICAUTH_PASSWORD: admin
    ports:
      - "8081:8081"
    depends_on:
      - mongodb
    networks:
      - microservices-network

volumes:
  postgres_data:
  mongodb_data:

networks:
  microservices-network:
    driver: bridge
```

### Iniciar la Infraestructura

```bash
# Iniciar todos los servicios
docker-compose up -d

# Verificar que estén corriendo
docker-compose ps

# Ver logs
docker-compose logs -f

# Detener todo
docker-compose down

# Detener y eliminar volúmenes (⚠️ borra datos)
docker-compose down -v
```

### Acceso a las Herramientas de Gestión

| Servicio | URL | Credenciales |
|----------|-----|--------------|
| **pgAdmin** | http://localhost:5050 | admin@admin.com / admin |
| **Mongo Express** | http://localhost:8081 | admin / admin |
| **PostgreSQL** | localhost:5432 | admin / admin123 |
| **MongoDB** | localhost:27017 | admin / admin123 |

## 🔐 Paso 4: Auth Service - Estructura Básica

### auth-service/pom.xml

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 
         http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <parent>
        <groupId>com.example.microservices</groupId>
        <artifactId>microservices-hexagonal</artifactId>
        <version>1.0.0</version>
    </parent>

    <artifactId>auth-service</artifactId>
    <name>Auth Service</name>

    <dependencies>
        <!-- Common module -->
        <dependency>
            <groupId>com.example.microservices</groupId>
            <artifactId>common</artifactId>
        </dependency>

        <!-- Spring Boot -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-data-jpa</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-validation</artifactId>
        </dependency>

        <!-- PostgreSQL -->
        <dependency>
            <groupId>org.postgresql</groupId>
            <artifactId>postgresql</artifactId>
            <scope>runtime</scope>
        </dependency>

        <!-- JWT -->
        <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt-api</artifactId>
        </dependency>
        <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt-impl</artifactId>
            <scope>runtime</scope>
        </dependency>
        <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt-jackson</artifactId>
            <scope>runtime</scope>
        </dependency>

        <!-- MapStruct -->
        <dependency>
            <groupId>org.mapstruct</groupId>
            <artifactId>mapstruct</artifactId>
        </dependency>

        <!-- Lombok -->
        <dependency>
            <groupId>org.projectlombok</groupId>
            <artifactId>lombok</artifactId>
            <optional>true</optional>
        </dependency>
    </dependencies>

    <build>
        <plugins>
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
            </plugin>
        </plugins>
    </build>
</project>
```

### auth-service/src/main/resources/application.yml

```yaml
spring:
  application:
    name: auth-service
  profiles:
    active: dev

server:
  port: 8081
```

### auth-service/src/main/resources/application-dev.yml

```yaml
spring:
  datasource:
    url: jdbc:postgresql://localhost:5432/authdb
    username: admin
    password: admin123
    driver-class-name: org.postgresql.Driver
    
  jpa:
    hibernate:
      ddl-auto: update
    show-sql: true
    properties:
      hibernate:
        dialect: org.hibernate.dialect.PostgreSQLDialect
        format_sql: true

# JWT Configuration
jwt:
  expiration: 86400000  # 24 horas en milisegundos
  issuer: auth-service
  private-key-path: certs/private_key.pem
  public-key-path: certs/public_key.pem

# Logging
logging:
  level:
    com.example.microservices: DEBUG
    org.springframework.security: DEBUG
```

## 📦 Paso 5: Product Service - Estructura Básica

### product-service/pom.xml

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 
         http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <parent>
        <groupId>com.example.microservices</groupId>
        <artifactId>microservices-hexagonal</artifactId>
        <version>1.0.0</version>
    </parent>

    <artifactId>product-service</artifactId>
    <name>Product Service</name>

    <dependencies>
        <!-- Common module -->
        <dependency>
            <groupId>com.example.microservices</groupId>
            <artifactId>common</artifactId>
        </dependency>

        <!-- Spring Boot -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-data-mongodb</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-validation</artifactId>
        </dependency>

        <!-- JWT (solo validación) -->
        <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt-api</artifactId>
        </dependency>
        <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt-impl</artifactId>
            <scope>runtime</scope>
        </dependency>
        <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt-jackson</artifactId>
            <scope>runtime</scope>
        </dependency>

        <!-- MapStruct -->
        <dependency>
            <groupId>org.mapstruct</groupId>
            <artifactId>mapstruct</artifactId>
        </dependency>

        <!-- Lombok -->
        <dependency>
            <groupId>org.projectlombok</groupId>
            <artifactId>lombok</artifactId>
            <optional>true</optional>
        </dependency>
    </dependencies>

    <build>
        <plugins>
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
            </plugin>
        </plugins>
    </build>
</project>
```

### product-service/src/main/resources/application-dev.yml

```yaml
spring:
  data:
    mongodb:
      host: localhost
      port: 27017
      database: productdb
      username: admin
      password: admin123
      authentication-database: admin

# JWT Configuration (solo validación)
jwt:
  issuer: auth-service
  public-key-path: certs/public_key.pem

# Logging
logging:
  level:
    com.example.microservices: DEBUG
    org.springframework.data.mongodb: DEBUG
```

## 🔨 Paso 6: Compilar el Proyecto

```bash
# Desde la raíz del proyecto
mvn clean install

# Compilar solo un módulo
cd auth-service
mvn clean install

# Saltar tests
mvn clean install -DskipTests

# Ver árbol de dependencias
mvn dependency:tree
```

## ✅ Verificación del Setup

### Checklist de Verificación:

- [ ] Parent POM configurado con módulos
- [ ] Módulo `common` compilando
- [ ] `auth-service` compilando
- [ ] `product-service` compilando
- [ ] Docker Compose levantado
- [ ] PostgreSQL accesible en :5432
- [ ] MongoDB accesible en :27017
- [ ] pgAdmin accesible en :5050
- [ ] Mongo Express accesible en :8081

### Comandos de Verificación:

```bash
# Verificar compilación
mvn clean install

# Verificar Docker
docker-compose ps

# Probar conexión a PostgreSQL
psql -h localhost -U admin -d authdb

# Probar conexión a MongoDB
mongosh mongodb://admin:admin123@localhost:27017/productdb
```

## 📊 Diagrama de Dependencias

```mermaid
graph TD
    PARENT[Parent POM<br/>microservices-hexagonal]
    COMMON[Common Module<br/>DTOs y Utilidades]
    AUTH[Auth Service<br/>PostgreSQL + JWT]
    PRODUCT[Product Service<br/>MongoDB + JWT Validation]
    
    PARENT --> COMMON
    PARENT --> AUTH
    PARENT --> PRODUCT
    AUTH --> COMMON
    PRODUCT --> COMMON
    
    style PARENT fill:#4A90E2,color:#fff
    style COMMON fill:#FFA500,color:#fff
    style AUTH fill:#50C878,color:#fff
    style PRODUCT fill:#9370DB,color:#fff
```

## 🎯 Mejores Prácticas Aplicadas

> [!TIP]
> **Separación de Configuraciones**: Usa profiles (`dev`, `prod`) para diferentes entornos.

1. **Maven Multi-Módulo**
   - Versiones centralizadas en parent POM
   - Dependencias comunes en `dependencyManagement`
   - Cada servicio es independiente

2. **Configuración Externalizada**
   - `application.yml` para configuración base
   - `application-dev.yml` para desarrollo
   - Variables de entorno para producción

3. **Docker Compose**
   - Infraestructura como código
   - Fácil de levantar y destruir
   - Aislamiento de servicios

4. **Módulo Common**
   - Evita duplicación de código
   - DTOs compartidos
   - Utilidades reutilizables

## 🚨 Errores Comunes y Soluciones

### Error: "Cannot resolve dependency"

```bash
# Solución: Instalar módulo common primero
cd common
mvn clean install
cd ..
mvn clean install
```

### Error: "Port already in use"

```bash
# Solución: Cambiar puerto en docker-compose.yml o detener servicio
docker-compose down
# O cambiar puerto en application.yml
```

### Error: "Connection refused" a PostgreSQL

```bash
# Solución: Verificar que Docker esté corriendo
docker-compose ps
docker-compose up -d postgres
```

## 📚 Próximo Artículo

En **Parte 3: Implementación del Auth Service**, veremos:
- Diseño del dominio (User, Role)
- Implementación de puertos y adaptadores
- Generación de JWT con RSA
- Spring Security configuración
- Endpoints de registro y login

## 🔗 Código Completo

El código completo de este setup está disponible en el repositorio del proyecto.

---

**Serie Completa:**
1. Introducción a la Arquitectura Hexagonal
2. **Setup del Proyecto Multi-Módulo** ← Estás aquí
3. Implementación del Auth Service
4. Implementación del Product Service
5. Seguridad con JWT y RSA
6. Patrones y Mejores Prácticas
7. Testing y Deployment

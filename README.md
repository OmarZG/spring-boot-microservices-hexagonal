# Microservices Hexagonal Architecture

Implementación completa de microservicios con Spring Boot 3.4.1, Java 21, arquitectura hexagonal, JWT con firma RSA, y bases de datos PostgreSQL y MongoDB.

## 🏗️ Arquitectura

Este proyecto implementa dos microservicios independientes siguiendo la arquitectura hexagonal (puertos y adaptadores):

### Auth Service (Puerto 8081)
- **Base de datos**: PostgreSQL
- **Responsabilidad**: Autenticación y gestión de usuarios
- **Características**:
  - Registro y login de usuarios
  - Generación de JWT firmado con RSA
  - Gestión de roles (ADMIN, USER, MODERATOR)
  - Encriptación de contraseñas con BCrypt

### Product Service (Puerto 8082)
- **Base de datos**: MongoDB
- **Responsabilidad**: Catálogo de productos
- **Características**:
  - CRUD completo de productos
  - Validación de JWT (usando clave pública)
  - Categorización de productos
  - Soporte para reviews y stock

## 📦 Estructura del Proyecto

```
microservices-hexagonal/
├── common/                    # Módulo compartido
│   └── ApiResponse, ErrorResponse
├── auth-service/              # Servicio de autenticación
│   ├── domain/               # Lógica de negocio pura
│   ├── application/          # Casos de uso
│   ├── infrastructure/       # Adaptadores (JPA, Security)
│   └── adapter/              # Controladores REST
└── product-service/          # Servicio de productos
    ├── domain/               # Lógica de negocio pura
    ├── application/          # Casos de uso
    ├── infrastructure/       # Adaptadores (MongoDB, Security)
    └── adapter/              # Controladores REST
```

## 🚀 Tecnologías

- **Java 21**
- **Spring Boot 3.4.1**
- **Spring Security** con JWT
- **PostgreSQL 16** (auth-service)
- **MongoDB 7** (product-service)
- **MapStruct 1.6.3** para mapeo de objetos
- **Lombok** para reducir boilerplate
- **JJWT 0.12.6** para JWT con firma RSA
- **Docker Compose** para infraestructura

## 📋 Requisitos Previos

- Java 21 o superior
- Maven 3.8+
- Docker y Docker Compose

## 🔧 Configuración e Instalación

### 1. Clonar el repositorio

```bash
cd microservices-hexagonal
```

### 2. Iniciar la infraestructura con Docker

```bash
docker-compose up -d
```

Esto iniciará:
- PostgreSQL en puerto 5432
- pgAdmin en http://localhost:5050 (admin@admin.com / admin)
- MongoDB en puerto 27017
- Mongo Express en http://localhost:8081 (admin / admin)

### 3. Generar claves RSA

```bash
cd auth-service
mvn compile exec:java -Dexec.mainClass="com.example.microservices.auth.infrastructure.util.KeyGenerator"
```

Esto generará:
- `auth-service/src/main/resources/certs/private_key.pem`
- `auth-service/src/main/resources/certs/public_key.pem`

### 4. Copiar clave pública al product-service

```bash
# Windows PowerShell
mkdir product-service\src\main\resources\certs
copy auth-service\src\main\resources\certs\public_key.pem product-service\src\main\resources\certs\

# Linux/Mac
mkdir -p product-service/src/main/resources/certs
cp auth-service/src/main/resources/certs/public_key.pem product-service/src/main/resources/certs/
```

### 5. Compilar el proyecto

```bash
mvn clean install
```

### 6. Iniciar los servicios

**Terminal 1 - Auth Service:**
```bash
cd auth-service
mvn spring-boot:run
```

**Terminal 2 - Product Service:**
```bash
cd product-service
mvn spring-boot:run
```

## 📡 API Endpoints

### Auth Service (http://localhost:8081)

#### Registrar Usuario
```bash
POST /api/auth/register
Content-Type: application/json

{
  "username": "testuser",
  "email": "test@example.com",
  "password": "Password123!",
  "roles": ["USER"]
}
```

#### Login
```bash
POST /api/auth/login
Content-Type: application/json

{
  "username": "testuser",
  "password": "Password123!"
}
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
      "username": "testuser",
      "email": "test@example.com",
      "roles": ["USER"],
      "enabled": true
    }
  },
  "timestamp": "2025-11-22T22:00:00Z"
}
```

#### Obtener Usuario Actual
```bash
GET /api/auth/me
Authorization: Bearer {token}
```

### Product Service (http://localhost:8082)

**Nota**: Todos los endpoints requieren autenticación con JWT.

#### Listar Productos
```bash
GET /api/products
Authorization: Bearer {token}
```

#### Obtener Producto
```bash
GET /api/products/{id}
Authorization: Bearer {token}
```

#### Crear Producto
```bash
POST /api/products
Authorization: Bearer {token}
Content-Type: application/json

{
  "name": "Laptop Gaming",
  "description": "Laptop de alto rendimiento",
  "price": 1299.99,
  "category": "ELECTRONICS",
  "stock": 50,
  "images": ["https://example.com/image1.jpg"]
}
```

#### Actualizar Producto
```bash
PUT /api/products/{id}
Authorization: Bearer {token}
Content-Type: application/json

{
  "price": 1199.99,
  "stock": 45
}
```

#### Eliminar Producto
```bash
DELETE /api/products/{id}
Authorization: Bearer {token}
```

## 🔐 Seguridad

- **JWT firmado con RSA 2048-bit**
- **Contraseñas encriptadas con BCrypt**
- **Tokens con expiración de 24 horas**
- **Validación de tokens en product-service usando clave pública**
- **Roles y permisos granulares**

## 📊 Respuestas Estandarizadas

### Respuesta Exitosa (ApiResponse)
```json
{
  "code": "SUCCESS",
  "message": "Request processed successfully",
  "data": { ... },
  "timestamp": "2025-11-22T22:00:00Z"
}
```

### Respuesta de Error (ErrorResponse)
```json
{
  "errorCode": "PRODUCT_NOT_FOUND",
  "message": "Product not found with id: 123",
  "status": 404,
  "timestamp": "2025-11-22T22:00:00Z"
}
```

### Errores de Validación
```json
{
  "errorCode": "VALIDATION_ERROR",
  "message": "Validation failed",
  "status": 400,
  "fieldErrors": [
    {
      "field": "price",
      "message": "Price must be greater than 0",
      "rejectedValue": -10
    }
  ],
  "timestamp": "2025-11-22T22:00:00Z"
}
```

## 🧪 Pruebas con cURL

### 1. Registrar usuario
```bash
curl -X POST http://localhost:8081/api/auth/register \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"admin\",\"email\":\"admin@example.com\",\"password\":\"Admin123!\",\"roles\":[\"ADMIN\"]}"
```

### 2. Login
```bash
curl -X POST http://localhost:8081/api/auth/login \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"admin\",\"password\":\"Admin123!\"}"
```

### 3. Crear producto (usando el token del login)
```bash
curl -X POST http://localhost:8082/api/products \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -d "{\"name\":\"Laptop\",\"description\":\"High-performance laptop\",\"price\":999.99,\"category\":\"ELECTRONICS\",\"stock\":10}"
```

## 🎯 Características Implementadas

✅ Arquitectura Hexagonal (Puertos y Adaptadores)  
✅ Spring Boot 3.4.1 con Java 21  
✅ JWT firmado con RSA  
✅ PostgreSQL para usuarios (JPA)  
✅ MongoDB para productos  
✅ MapStruct para mapeo de objetos  
✅ Records de Java para DTOs  
✅ Lombok para reducir boilerplate  
✅ RestControllerAdvice para manejo global de excepciones  
✅ Respuestas estandarizadas (ApiResponse/ErrorResponse)  
✅ Validación con Bean Validation  
✅ Configuración externalizada  
✅ Enums para roles y categorías  
✅ Docker Compose para infraestructura  
✅ Auditoría automática (createdAt, updatedAt)  
✅ CORS configurado  
✅ Logging estructurado  

## 📝 Notas Importantes

1. **Claves RSA**: Las claves RSA NO deben ser commiteadas al repositorio. Están en `.gitignore`.
2. **Seguridad**: En producción, usar variables de entorno para credenciales.
3. **Perfiles**: Usar `spring.profiles.active=prod` en producción.
4. **Puertos**: Auth-service (8081), Product-service (8082), Mongo Express (8081).

## 🛠️ Troubleshooting

### Error: "Could not load RSA keys"
- Asegúrate de haber generado las claves con KeyGenerator
- Verifica que los archivos .pem existan en `auth-service/src/main/resources/certs/`

### Error: "Connection refused" a PostgreSQL/MongoDB
- Verifica que Docker Compose esté corriendo: `docker-compose ps`
- Reinicia los contenedores: `docker-compose restart`

### Error de compilación con MapStruct
- Ejecuta `mvn clean install` desde la raíz del proyecto
- Verifica que Java 21 esté configurado correctamente

## 📄 Licencia

Este proyecto es un ejemplo educativo de arquitectura hexagonal con Spring Boot.

## 👥 Autor

Implementación completa siguiendo las mejores prácticas de Spring Boot y arquitectura hexagonal.

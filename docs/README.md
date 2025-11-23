# 📚 Documentación: Microservicios con Arquitectura Hexagonal

Bienvenido a la serie completa de artículos sobre cómo construir microservicios profesionales usando Spring Boot 3, Java 21, y Arquitectura Hexagonal.

## 🎯 Sobre Esta Serie

Esta serie de 7 artículos te guiará paso a paso en la construcción de un sistema completo de microservicios, aplicando las mejores prácticas de la industria y patrones de diseño probados.

**Proyecto completo:** Sistema de autenticación y catálogo de productos con:
- 🔐 Auth Service (PostgreSQL + JWT con RSA)
- 📦 Product Service (MongoDB + Validación JWT)
- 🏗️ Arquitectura Hexagonal
- 🔒 Seguridad robusta con RBAC
- 🧪 Testing completo
- 🚀 CI/CD automatizado

## 📖 Artículos de la Serie

### [Parte 1: Introducción a la Arquitectura Hexagonal](./01-introduccion-arquitectura-hexagonal.md)

**Conceptos fundamentales**
- ¿Qué es la arquitectura hexagonal?
- Ventajas sobre arquitecturas tradicionales
- Puertos y adaptadores
- Separación de responsabilidades
- Cuándo usar esta arquitectura

**Aprenderás:**
- Los principios de diseño hexagonal
- Cómo estructurar tu código en capas
- La diferencia entre dominio, aplicación e infraestructura

---

### [Parte 2: Setup del Proyecto Multi-Módulo](./02-setup-proyecto-microservicios.md)

**Configuración del proyecto**
- Maven multi-módulo
- Docker Compose para infraestructura
- Configuración de PostgreSQL y MongoDB
- Estructura de directorios
- Módulo común compartido

**Aprenderás:**
- Cómo organizar un proyecto multi-módulo
- Configurar bases de datos con Docker
- Gestión centralizada de dependencias

---

### [Parte 3: Implementación del Auth Service](./03-implementacion-auth-service.md)

**Servicio de autenticación completo**
- Diseño del dominio (User, Role)
- Puertos y adaptadores
- JWT con firma RSA
- Spring Security
- Endpoints de registro y login

**Aprenderás:**
- Implementar arquitectura hexagonal en la práctica
- Generar y firmar JWT con RSA
- Configurar Spring Security
- Sistema de roles y permisos

---

### [Parte 4: Implementación del Product Service](./04-implementacion-product-service.md)

**Servicio de productos con MongoDB**
- Modelo de dominio Product
- Spring Data MongoDB
- Validación de JWT
- Autorización basada en permisos
- CRUD completo

**Aprenderás:**
- Integrar MongoDB en arquitectura hexagonal
- Validar JWT sin generarlos
- Implementar control de acceso granular
- Manejar documentos NoSQL

---

### [Parte 5: Seguridad con JWT y RSA](./05-seguridad-jwt-rsa.md)

**Deep dive en seguridad**
- Anatomía de un JWT
- Criptografía RSA explicada
- Firma y validación de tokens
- Control de acceso basado en roles (RBAC)
- Mejores prácticas de seguridad

**Aprenderás:**
- Cómo funciona JWT internamente
- Por qué usar RSA sobre HMAC
- Implementar RBAC correctamente
- Rotación de claves y seguridad en producción

---

### [Parte 6: Patrones y Mejores Prácticas](./06-patrones-mejores-practicas.md)

**Código de calidad profesional**
- MapStruct para mapeo eficiente
- Manejo global de excepciones
- Validaciones con Bean Validation
- DTOs vs Entities
- Logging estructurado
- Respuestas estandarizadas

**Aprenderás:**
- Patrones de diseño aplicados
- Cómo evitar código repetitivo
- Manejo robusto de errores
- Logging efectivo

---

### [Parte 7: Testing y Deployment](./07-testing-deployment.md)

**De desarrollo a producción**
- Tests unitarios con JUnit 5 y Mockito
- Tests de integración con Testcontainers
- Pruebas con Postman
- Containerización con Docker
- CI/CD con GitHub Actions
- Monitoreo y observabilidad

**Aprenderás:**
- Estrategia completa de testing
- Dockerizar microservicios
- Automatizar deployment
- Configurar monitoreo

---

## 🛠️ Tecnologías Utilizadas

| Categoría | Tecnología | Versión |
|-----------|-----------|---------|
| **Lenguaje** | Java | 21 |
| **Framework** | Spring Boot | 3.5.8 |
| **Build Tool** | Maven | 3.8+ |
| **Seguridad** | Spring Security + JWT | - |
| **Base de Datos** | PostgreSQL | 16 |
| **NoSQL** | MongoDB | 7 |
| **Mapeo** | MapStruct | 1.6.3 |
| **JWT** | JJWT | 0.12.6 |
| **Testing** | JUnit 5 + Mockito | - |
| **Containers** | Docker + Docker Compose | - |
| **CI/CD** | GitHub Actions | - |

## 📊 Arquitectura del Sistema

```
┌─────────────────────────────────────────────────────────────┐
│                         Client Layer                         │
│                    (Postman, Web, Mobile)                    │
└──────────────────────┬──────────────────────────────────────┘
                       │
         ┌─────────────┴─────────────┐
         │                           │
         ▼                           ▼
┌─────────────────┐         ┌─────────────────┐
│  Auth Service   │         │ Product Service │
│    (Port 8081)  │         │    (Port 8082)  │
│                 │         │                 │
│  - Register     │         │  - CRUD         │
│  - Login        │         │  - Categories   │
│  - JWT Gen      │◄────────┤  - JWT Valid    │
│                 │  Public │  - RBAC         │
│  PostgreSQL     │   Key   │  MongoDB        │
└─────────────────┘         └─────────────────┘
```

## 🎓 ¿Para Quién Es Esta Serie?

Esta serie es ideal para:

- ✅ Desarrolladores Java que quieren aprender arquitectura hexagonal
- ✅ Equipos que buscan implementar microservicios mantenibles
- ✅ Arquitectos de software explorando patrones modernos
- ✅ Estudiantes avanzados de ingeniería de software
- ✅ Profesionales que quieren mejorar sus habilidades en Spring Boot

**Prerequisitos:**
- Conocimientos básicos de Java
- Familiaridad con Spring Boot
- Entendimiento de REST APIs
- Conceptos básicos de bases de datos

## 🚀 Cómo Usar Esta Documentación

### Opción 1: Lectura Secuencial (Recomendado)

Lee los artículos en orden del 1 al 7. Cada artículo construye sobre los conceptos del anterior.

### Opción 2: Consulta por Tema

Usa el índice arriba para saltar directamente al tema que te interesa:
- ¿Necesitas entender JWT? → Parte 5
- ¿Quieres configurar testing? → Parte 7
- ¿Buscas patrones de código? → Parte 6

### Opción 3: Implementación Práctica

1. Lee la Parte 1 para entender los conceptos
2. Sigue la Parte 2 para configurar tu entorno
3. Implementa siguiendo las Partes 3 y 4
4. Refina con las Partes 5, 6 y 7

## 💡 Conceptos Clave Cubiertos

### Arquitectura
- ✅ Hexagonal Architecture (Ports & Adapters)
- ✅ Domain-Driven Design (DDD)
- ✅ Separation of Concerns
- ✅ Dependency Inversion

### Seguridad
- ✅ JWT con firma RSA 2048-bit
- ✅ Role-Based Access Control (RBAC)
- ✅ Spring Security
- ✅ Password encryption con BCrypt

### Mejores Prácticas
- ✅ MapStruct para mapeo eficiente
- ✅ DTOs separados de entidades
- ✅ Global exception handling
- ✅ Bean Validation
- ✅ Structured logging

### Testing
- ✅ Unit tests (JUnit 5 + Mockito)
- ✅ Integration tests (Testcontainers)
- ✅ API tests (Postman)
- ✅ Test pyramid strategy

### DevOps
- ✅ Docker multi-stage builds
- ✅ Docker Compose orchestration
- ✅ CI/CD con GitHub Actions
- ✅ Health checks y monitoring

## 📁 Estructura del Proyecto

```
microservices-hexagonal/
├── docs/                                    # Esta documentación
│   ├── README.md                           # Este archivo
│   ├── 01-introduccion-arquitectura-hexagonal.md
│   ├── 02-setup-proyecto-microservicios.md
│   ├── 03-implementacion-auth-service.md
│   ├── 04-implementacion-product-service.md
│   ├── 05-seguridad-jwt-rsa.md
│   ├── 06-patrones-mejores-practicas.md
│   └── 07-testing-deployment.md
│
├── common/                                  # Módulo compartido
├── auth-service/                           # Servicio de autenticación
├── product-service/                        # Servicio de productos
├── docker-compose.yml                      # Infraestructura
├── pom.xml                                 # Parent POM
└── README.md                               # README principal
```

## 🤝 Contribuciones

Si encuentras errores, tienes sugerencias o quieres contribuir:

1. Abre un issue describiendo el problema o mejora
2. Haz un fork del repositorio
3. Crea una rama para tu feature
4. Envía un pull request

## 📝 Notas Finales

Esta documentación está diseñada para ser:
- **Práctica**: Código real que funciona
- **Educativa**: Explicaciones detalladas de conceptos
- **Completa**: Desde setup hasta deployment
- **Actualizada**: Usando las últimas versiones estables

## 🔗 Enlaces Útiles

- [Código fuente del proyecto](../)
- [Colección de Postman](../MicroservicesHexagonal-CompleteAPI_Tests.postman_collection.json)
- [README principal](../README.md)

---

**¡Feliz aprendizaje!** 🚀

Si esta serie te resulta útil, considera compartirla con otros desarrolladores que puedan beneficiarse.

---

*Última actualización: Noviembre 2025*

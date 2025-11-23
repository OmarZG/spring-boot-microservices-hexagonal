# Seguridad con JWT y RSA: Firma Digital en Microservicios

> **Serie: Construyendo Microservicios con Spring Boot y Arquitectura Hexagonal**  
> Parte 5 de 7 - JWT con Firma RSA

## 📖 Introducción

La seguridad es fundamental en arquitecturas de microservicios. En este artículo profundizaremos en cómo implementamos autenticación y autorización usando **JWT (JSON Web Tokens)** firmados con **RSA 2048-bit**.

**Temas que cubriremos:**
- 🔐 ¿Qué es JWT y cómo funciona?
- 🔑 Criptografía asimétrica (RSA)
- ✍️ Firma y validación de tokens
- 🛡️ Control de acceso basado en roles (RBAC)
- 🔄 Mejores prácticas de seguridad

## 🎯 ¿Por Qué JWT con RSA?

### Alternativas y sus Limitaciones

| Método | Pros | Contras |
|--------|------|---------|
| **Session Cookies** | Simple, bien soportado | Stateful, no escala en microservicios |
| **JWT con HMAC** | Stateless, rápido | Clave simétrica compartida (riesgo) |
| **JWT con RSA** | Stateless, clave pública distribuible | Más lento que HMAC |
| **OAuth2** | Estándar, robusto | Complejo de implementar |

### Nuestra Elección: JWT + RSA

```mermaid
graph LR
    subgraph "Auth Service"
        PK[Private Key<br/>🔒 Secreta]
        SIGN[Firma JWT]
    end
    
    subgraph "Product Service"
        PUBK[Public Key<br/>🔓 Pública]
        VERIFY[Valida JWT]
    end
    
    subgraph "Other Services"
        PUBK2[Public Key<br/>🔓 Pública]
        VERIFY2[Valida JWT]
    end
    
    PK --> SIGN
    SIGN -->|JWT Firmado| VERIFY
    SIGN -->|JWT Firmado| VERIFY2
    PUBK --> VERIFY
    PUBK2 --> VERIFY2
    
    style PK fill:#E74C3C,color:#fff
    style PUBK fill:#27AE60,color:#fff
    style PUBK2 fill:#27AE60,color:#fff
```

**Ventajas:**
- ✅ **Stateless**: No requiere almacenar sesiones
- ✅ **Escalable**: Cada servicio valida independientemente
- ✅ **Seguro**: Solo auth-service puede firmar tokens
- ✅ **Distribuible**: Clave pública se puede compartir

## 🔐 Anatomía de un JWT

Un JWT consta de tres partes separadas por puntos (`.`):

```
eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhZG1pbiIsImlhdCI6MTYzOTk...
└─────── Header ──────┘ └────────── Payload ──────────┘ └─ Signature ─┘
```

### 1. Header (Encabezado)

```json
{
  "alg": "RS256",
  "typ": "JWT"
}
```

- **alg**: Algoritmo de firma (RS256 = RSA con SHA-256)
- **typ**: Tipo de token (JWT)

### 2. Payload (Carga Útil)

```json
{
  "sub": "admin",
  "iat": 1763906248,
  "exp": 1763992648,
  "iss": "auth-service",
  "roles": "product:read,product:create,ROLE_ADMIN"
}
```

**Claims estándar:**
- **sub** (subject): Identificador del usuario
- **iat** (issued at): Timestamp de creación
- **exp** (expiration): Timestamp de expiración
- **iss** (issuer): Quién emitió el token

**Claims personalizados:**
- **roles**: Permisos del usuario

### 3. Signature (Firma)

```
RSASHA256(
  base64UrlEncode(header) + "." + base64UrlEncode(payload),
  privateKey
)
```

La firma garantiza:
- ✅ **Integridad**: El token no ha sido modificado
- ✅ **Autenticidad**: Fue creado por quien tiene la clave privada

## 🔑 Criptografía RSA

### Conceptos Básicos

RSA es un algoritmo de **criptografía asimétrica**:

```mermaid
graph TB
    subgraph "Generación de Claves"
        GEN[Generar Par de Claves]
        GEN --> PRIV[Private Key 🔒<br/>Mantener Secreta]
        GEN --> PUB[Public Key 🔓<br/>Compartir Libremente]
    end
    
    subgraph "Firma"
        MSG[Mensaje]
        PRIV --> SIGN[Firmar]
        MSG --> SIGN
        SIGN --> SIG[Firma Digital]
    end
    
    subgraph "Verificación"
        MSG2[Mensaje]
        SIG2[Firma Digital]
        PUB --> VERIFY[Verificar]
        MSG2 --> VERIFY
        SIG2 --> VERIFY
        VERIFY --> VALID{¿Válida?}
    end
    
    style PRIV fill:#E74C3C,color:#fff
    style PUB fill:#27AE60,color:#fff
```

### Generación de Claves RSA

Nuestro `KeyGenerator`:

```java
public class KeyGenerator {
    public static void main(String[] args) throws Exception {
        // 1. Generar par de claves RSA de 2048 bits
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair pair = keyGen.generateKeyPair();
        
        PrivateKey privateKey = pair.getPrivate();
        PublicKey publicKey = pair.getPublic();
        
        // 2. Guardar en formato PEM
        savePrivateKey(privateKey);
        savePublicKey(publicKey);
    }
}
```

**¿Por qué 2048 bits?**
- 1024 bits: ❌ Inseguro (puede ser crackeado)
- 2048 bits: ✅ Seguro hasta ~2030
- 4096 bits: ✅ Muy seguro pero más lento

### Formato PEM

```
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC...
-----END PRIVATE KEY-----
```

```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvL8QEh...
-----END PUBLIC KEY-----
```

## ✍️ Proceso de Firma y Validación

### Flujo Completo

```mermaid
sequenceDiagram
    participant U as Usuario
    participant AUTH as Auth Service
    participant PROD as Product Service
    
    Note over U,AUTH: 1. Autenticación
    U->>AUTH: POST /login<br/>{username, password}
    AUTH->>AUTH: Validar credenciales
    AUTH->>AUTH: Cargar Private Key
    AUTH->>AUTH: Generar JWT<br/>+ Firmar con RSA
    AUTH-->>U: JWT Token
    
    Note over U,PROD: 2. Acceso a Recurso
    U->>PROD: GET /products<br/>Authorization: Bearer {JWT}
    PROD->>PROD: Extraer JWT del header
    PROD->>PROD: Cargar Public Key
    PROD->>PROD: Verificar firma RSA
    alt Firma válida
        PROD->>PROD: Extraer roles del payload
        PROD->>PROD: Verificar permisos
        PROD-->>U: 200 OK + Productos
    else Firma inválida
        PROD-->>U: 403 Forbidden
    end
```

### Implementación: Generación de Token

```java
@Component
public class JwtTokenProvider {
    
    @Value("${jwt.expiration}")
    private Long jwtExpiration; // 86400000 ms = 24 horas
    
    @Value("${jwt.issuer}")
    private String jwtIssuer; // "auth-service"
    
    private PrivateKey privateKey;
    
    public String generateToken(Authentication authentication) {
        // 1. Obtener información del usuario
        String username = authentication.getName();
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + jwtExpiration);
        
        // 2. Extraer roles y permisos
        String roles = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));
        // Resultado: "product:read,product:create,ROLE_ADMIN"
        
        // 3. Construir y firmar JWT
        return Jwts.builder()
                .subject(username)              // "admin"
                .issuedAt(now)                  // Timestamp actual
                .expiration(expiryDate)         // now + 24h
                .issuer(jwtIssuer)              // "auth-service"
                .claim("roles", roles)          // Custom claim
                .signWith(privateKey, Jwts.SIG.RS256)  // Firma RSA
                .compact();
    }
}
```

**Resultado:**
```
eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhZG1pbiIsImlhdCI6MTYzOTkwNjI0OCwiZXhwIjoxNjM5OTkyNjQ4LCJpc3MiOiJhdXRoLXNlcnZpY2UiLCJyb2xlcyI6InByb2R1Y3Q6cmVhZCxwcm9kdWN0OmNyZWF0ZSxST0xFX0FETUlOIn0.signature...
```

### Implementación: Validación de Token

```java
@Component
public class JwtTokenValidator {
    
    private PublicKey publicKey;
    
    public boolean validateToken(String token) {
        try {
            // 1. Parsear y verificar firma
            Jwts.parser()
                    .verifyWith(publicKey)      // Usar clave pública
                    .build()
                    .parseSignedClaims(token);  // Lanza excepción si inválido
            
            return true;
        } catch (ExpiredJwtException ex) {
            log.error("Token expirado");
            return false;
        } catch (MalformedJwtException ex) {
            log.error("Token malformado");
            return false;
        } catch (SecurityException ex) {
            log.error("Firma inválida");
            return false;
        }
    }
    
    public List<String> getRolesFromToken(String token) {
        Claims claims = Jwts.parser()
                .verifyWith(publicKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
        
        String rolesString = claims.get("roles", String.class);
        return Arrays.asList(rolesString.split(","));
        // ["product:read", "product:create", "ROLE_ADMIN"]
    }
}
```

## 🛡️ Control de Acceso Basado en Roles (RBAC)

### Diseño del Sistema de Permisos

```mermaid
graph TB
    subgraph "Roles"
        USER[USER]
        MOD[MODERATOR]
        ADMIN[ADMIN]
    end
    
    subgraph "Permisos"
        P1[product:read]
        P2[product:create]
        P3[product:update]
        P4[product:delete]
        P5[user:read]
        P6[user:update]
        P7[admin:all]
    end
    
    USER --> P1
    MOD --> P1
    MOD --> P2
    MOD --> P3
    MOD --> P5
    MOD --> P6
    ADMIN --> P1
    ADMIN --> P2
    ADMIN --> P3
    ADMIN --> P4
    ADMIN --> P5
    ADMIN --> P6
    ADMIN --> P7
    
    style ADMIN fill:#E74C3C,color:#fff
    style MOD fill:#F39C12,color:#fff
    style USER fill:#3498DB,color:#fff
```

### Implementación: Enum de Roles

```java
public enum Role {
    USER(Set.of("product:read")),
    
    MODERATOR(Set.of(
        "user:read",
        "user:update",
        "product:read",
        "product:create",
        "product:update"
    )),
    
    ADMIN(Set.of(
        "user:read",
        "user:create",
        "user:update",
        "user:delete",
        "product:read",
        "product:create",
        "product:update",
        "product:delete",
        "admin:all"
    ));

    private final Set<String> permissions;

    public Collection<? extends GrantedAuthority> getAuthorities() {
        List<GrantedAuthority> authorities = permissions.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        // Agregar rol con prefijo ROLE_
        authorities.add(new SimpleGrantedAuthority("ROLE_" + this.name()));

        return authorities;
    }
}
```

### Autorización en Endpoints

```java
@RestController
@RequestMapping("/api/products")
public class ProductController {

    // ✅ USER, MODERATOR, ADMIN pueden leer
    @GetMapping
    @PreAuthorize("hasAnyAuthority('product:read', 'admin:all')")
    public ResponseEntity<List<ProductDTO>> getAllProducts() {
        // ...
    }

    // ✅ Solo MODERATOR y ADMIN pueden crear
    @PostMapping
    @PreAuthorize("hasAnyAuthority('product:create', 'admin:all')")
    public ResponseEntity<ProductDTO> createProduct(@RequestBody CreateProductRequest request) {
        // ...
    }

    // ✅ Solo ADMIN puede eliminar
    @DeleteMapping("/{id}")
    @PreAuthorize("hasAnyAuthority('product:delete', 'admin:all')")
    public ResponseEntity<Void> deleteProduct(@PathVariable String id) {
        // ...
    }
}
```

### Flujo de Autorización

```mermaid
sequenceDiagram
    participant C as Client
    participant F as JwtAuthenticationFilter
    participant V as JwtTokenValidator
    participant S as Spring Security
    participant CTRL as Controller

    C->>F: Request + JWT
    F->>V: validateToken(jwt)
    V-->>F: true
    F->>V: getRolesFromToken(jwt)
    V-->>F: ["product:read", "ROLE_USER"]
    F->>F: Create Authentication<br/>with authorities
    F->>S: Set SecurityContext
    F->>CTRL: Continue to controller
    CTRL->>S: @PreAuthorize check
    alt Has permission
        S-->>CTRL: ✅ Authorized
        CTRL-->>C: 200 OK
    else No permission
        S-->>CTRL: ❌ Access Denied
        CTRL-->>C: 403 Forbidden
    end
```

## 🔒 Mejores Prácticas de Seguridad

### 1. Expiración de Tokens

```yaml
jwt:
  expiration: 86400000  # 24 horas
```

**Recomendaciones:**
- ⏰ **Access Token**: 15 minutos - 1 hora
- 🔄 **Refresh Token**: 7-30 días
- 🚫 **Nunca**: Tokens sin expiración

### 2. Almacenamiento Seguro de Claves

```bash
# ❌ MAL: Claves en el repositorio
git add src/main/resources/certs/private_key.pem

# ✅ BIEN: Claves en .gitignore
echo "src/main/resources/certs/*.pem" >> .gitignore

# ✅ PRODUCCIÓN: Variables de entorno
export JWT_PRIVATE_KEY=$(cat /secure/path/private_key.pem)
```

### 3. HTTPS Obligatorio

```java
@Configuration
public class SecurityConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) {
        http
            .requiresChannel(channel -> channel
                .anyRequest().requiresSecure()  // Force HTTPS
            );
        return http.build();
    }
}
```

### 4. Validación Estricta

```java
public boolean validateToken(String token) {
    try {
        Claims claims = Jwts.parser()
                .verifyWith(publicKey)
                .requireIssuer("auth-service")  // ✅ Verificar issuer
                .build()
                .parseSignedClaims(token)
                .getPayload();
        
        // ✅ Verificar expiración manualmente también
        if (claims.getExpiration().before(new Date())) {
            return false;
        }
        
        return true;
    } catch (Exception e) {
        return false;
    }
}
```

### 5. Rate Limiting

```java
@Component
public class RateLimitFilter extends OncePerRequestFilter {
    
    private final Map<String, AtomicInteger> requestCounts = new ConcurrentHashMap<>();
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                    HttpServletResponse response,
                                    FilterChain filterChain) {
        String clientIp = request.getRemoteAddr();
        
        AtomicInteger count = requestCounts.computeIfAbsent(
            clientIp, k -> new AtomicInteger(0)
        );
        
        if (count.incrementAndGet() > 100) {  // 100 requests/minute
            response.setStatus(429);  // Too Many Requests
            return;
        }
        
        filterChain.doFilter(request, response);
    }
}
```

### 6. Rotación de Claves

```java
public class KeyRotationService {
    
    @Scheduled(cron = "0 0 0 1 * ?")  // Primer día de cada mes
    public void rotateKeys() {
        // 1. Generar nuevo par de claves
        KeyPair newPair = generateNewKeyPair();
        
        // 2. Guardar nueva clave privada
        savePrivateKey(newPair.getPrivate());
        
        // 3. Publicar nueva clave pública
        publishPublicKey(newPair.getPublic());
        
        // 4. Mantener clave anterior por período de gracia (7 días)
        scheduleOldKeyDeletion(7, TimeUnit.DAYS);
    }
}
```

## 🔍 Debugging y Troubleshooting

### Decodificar JWT

Usa [jwt.io](https://jwt.io) o:

```bash
# Extraer payload
echo "eyJzdWIiOiJhZG1pbiIsImlhdCI6MTYzOTkwNjI0OH0" | base64 -d
```

### Logs Útiles

```java
@Slf4j
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    
    @Override
    protected void doFilterInternal(...) {
        String jwt = getJwtFromRequest(request);
        
        if (jwt != null) {
            log.debug("JWT Token: {}", jwt.substring(0, 20) + "...");
            
            if (jwtTokenValidator.validateToken(jwt)) {
                String username = jwtTokenValidator.getUsernameFromToken(jwt);
                List<String> roles = jwtTokenValidator.getRolesFromToken(jwt);
                
                log.info("Authenticated user: {} with roles: {}", username, roles);
            } else {
                log.warn("Invalid JWT token");
            }
        }
    }
}
```

### Errores Comunes

| Error | Causa | Solución |
|-------|-------|----------|
| `Invalid JWT signature` | Clave pública incorrecta | Verificar que sea la misma del auth-service |
| `Expired JWT token` | Token expirado | Renovar token con login |
| `JWT claims string is empty` | Token malformado | Verificar formato Bearer {token} |
| `Could not load RSA keys` | Archivo no encontrado | Verificar ruta en application.yml |

## 📊 Comparación de Rendimiento

### HMAC vs RSA

```
Operación          | HMAC (HS256) | RSA (RS256)
-------------------|--------------|-------------
Firma (sign)       | 0.05 ms      | 2.5 ms
Verificación       | 0.05 ms      | 0.8 ms
Tamaño de clave    | 256 bits     | 2048 bits
Tamaño de firma    | 256 bits     | 2048 bits
```

**Conclusión:**
- HMAC es ~50x más rápido
- Pero RSA permite distribución segura de claves públicas
- Para microservicios, RSA es la mejor opción

## 🎯 Checklist de Seguridad

- [ ] Tokens con expiración configurada
- [ ] HTTPS en producción
- [ ] Claves privadas en .gitignore
- [ ] Validación estricta de issuer
- [ ] Rate limiting implementado
- [ ] Logs de autenticación
- [ ] Rotación de claves planificada
- [ ] Refresh tokens para UX
- [ ] Revocación de tokens (blacklist)
- [ ] Auditoría de accesos

## 📚 Próximo Artículo

En **Parte 6: Patrones y Mejores Prácticas**, veremos:
- MapStruct para mapeo eficiente
- Manejo global de excepciones
- Validaciones con Bean Validation
- DTOs vs Entities
- Logging estructurado

---

**Serie Completa:**
1. Introducción a la Arquitectura Hexagonal
2. Setup del Proyecto Multi-Módulo
3. Implementación del Auth Service
4. Implementación del Product Service
5. **Seguridad con JWT y RSA** ← Estás aquí
6. Patrones y Mejores Prácticas
7. Testing y Deployment

# Instrucciones para Subir a GitHub

## 📍 Ubicación del Proyecto
```
C:\Users\Techno\.gemini\antigravity\scratch\microservices-hexagonal
```

## 🔧 Estado Actual
✅ Repositorio Git inicializado localmente
✅ Todos los archivos agregados al staging
✅ Commit inicial creado

## 🚀 Pasos para Subir a GitHub

### 1. Crear Repositorio en GitHub
1. Ve a https://github.com/new
2. Nombre sugerido: `spring-boot-microservices-hexagonal`
3. Descripción: "Microservices with Spring Boot 3.4.1, Java 21, Hexagonal Architecture, JWT (RSA), PostgreSQL & MongoDB"
4. **NO** inicialices con README, .gitignore, o licencia (ya los tenemos)
5. Click en "Create repository"

### 2. Conectar Repositorio Local con GitHub

Después de crear el repositorio en GitHub, ejecuta estos comandos:

```bash
cd C:\Users\Techno\.gemini\antigravity\scratch\microservices-hexagonal

# Agregar el remote (reemplaza TU_USUARIO con tu usuario de GitHub)
git remote add origin https://github.com/TU_USUARIO/spring-boot-microservices-hexagonal.git

# Verificar el remote
git remote -v

# Subir el código
git push -u origin master
```

### 3. Alternativa: Usar SSH (Recomendado)

Si tienes configurado SSH:

```bash
git remote add origin git@github.com:TU_USUARIO/spring-boot-microservices-hexagonal.git
git push -u origin master
```

## 📝 Comandos Útiles

### Ver estado del repositorio
```bash
git status
```

### Ver historial de commits
```bash
git log --oneline
```

### Crear una nueva rama
```bash
git checkout -b develop
```

### Ver archivos ignorados
```bash
git status --ignored
```

## ⚠️ IMPORTANTE: Archivos Ignorados

El `.gitignore` está configurado para **NO** incluir:
- ✅ `*.pem` - Claves RSA (NUNCA deben ser commiteadas)
- ✅ `target/` - Archivos compilados
- ✅ `.idea/`, `.vscode/` - Configuración de IDEs
- ✅ `*.log` - Archivos de log

### Generar Claves RSA Después de Clonar

Cuando alguien clone el repositorio, deberá generar sus propias claves RSA:

```bash
cd auth-service
mvn compile exec:java -Dexec.mainClass="com.example.microservices.auth.infrastructure.util.KeyGenerator"

# Copiar clave pública al product-service
mkdir product-service\src\main\resources\certs
copy auth-service\src\main\resources\certs\public_key.pem product-service\src\main\resources\certs\
```

## 🔐 Seguridad

### Variables de Entorno para Producción

Cuando despliegues en producción, usa variables de entorno:

**Auth Service:**
```bash
DB_URL=jdbc:postgresql://tu-servidor:5432/authdb
DB_USERNAME=tu_usuario
DB_PASSWORD=tu_password_seguro
JWT_EXPIRATION=86400000
```

**Product Service:**
```bash
MONGODB_URI=mongodb://tu-servidor:27017/productdb
```

## 📊 Estructura del Repositorio

```
microservices-hexagonal/
├── .git/                      # Git repository
├── .gitignore                 # Archivos ignorados
├── README.md                  # Documentación principal
├── docker-compose.yml         # Infraestructura
├── pom.xml                    # POM padre
├── GITHUB_INSTRUCTIONS.md     # Este archivo
├── common/                    # Módulo compartido
├── auth-service/              # Servicio de autenticación
│   └── src/main/resources/certs/  # ⚠️ NO en Git (generadas localmente)
└── product-service/           # Servicio de productos
    └── src/main/resources/certs/  # ⚠️ NO en Git (copiadas localmente)
```

## 🎯 Próximos Pasos

1. ✅ Crear repositorio en GitHub
2. ✅ Conectar con `git remote add origin`
3. ✅ Hacer push: `git push -u origin master`
4. ✅ Agregar descripción y topics en GitHub
5. ✅ Crear un Release (opcional)

## 📌 Topics Sugeridos para GitHub

- `spring-boot`
- `java-21`
- `hexagonal-architecture`
- `microservices`
- `jwt`
- `rsa`
- `postgresql`
- `mongodb`
- `mapstruct`
- `docker-compose`
- `rest-api`

## 🔄 Workflow de Desarrollo

### Crear una nueva feature
```bash
git checkout -b feature/nombre-feature
# Hacer cambios
git add .
git commit -m "feat: descripción de la feature"
git push origin feature/nombre-feature
```

### Actualizar desde el repositorio remoto
```bash
git pull origin master
```

## 📄 Licencia

Considera agregar una licencia. Opciones populares:
- MIT License (muy permisiva)
- Apache License 2.0
- GPL v3

## 🤝 Contribuciones

Si quieres que otros contribuyan, crea un archivo `CONTRIBUTING.md` con las guías.

---

**Nota**: Este proyecto está listo para ser compartido. Asegúrate de revisar que no haya información sensible antes de hacer el repositorio público.

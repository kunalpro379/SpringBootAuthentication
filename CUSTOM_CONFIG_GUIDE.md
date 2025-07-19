# 🔧 Custom Configuration Guide

The Authentication Server supports custom configuration through an `app.config.yaml` file. This allows you to override default settings without modifying the application code.

## 📋 Quick Start

1. **Create Configuration File**
   ```bash
   # In your application directory, create:
   touch app.config.yaml
   ```

2. **Add Your Custom Settings**
   ```yaml
   # Example: Change server port and database
   server:
     port: 9090
   
   app:
     database:
       type: postgresql
       host: localhost
       username: myuser
       password: mypassword
   ```

3. **Restart Application**
   ```bash
   # The application will automatically detect and load your custom configuration
   mvn spring-boot:run
   ```

## 🎯 Configuration Sections

### 🖥️ Server Configuration
```yaml
server:
  port: 8080
  servlet:
    context-path: /
  # HTTPS Configuration (optional)
  ssl:
    enabled: false
    key-store: classpath:keystore.p12
    key-store-password: changeit
```

### 🗄️ Database Configuration
```yaml
app:
  database:
    type: postgresql  # Options: postgresql, mysql, mongodb, h2
    host: localhost
    port: 5432       # Auto-detected if not specified
    name: authdb
    username: postgres
    password: your_password
    
    # Connection Pool Settings
    pool:
      maximum-size: 20
      minimum-idle: 5
      connection-timeout: 30000
```

### 🔐 JWT Configuration
```yaml
jwt:
  # Use a strong, random secret key (minimum 32 characters)
  secret: "your-super-secret-jwt-key-here-make-it-long-and-random"
  expiration: 86400000      # 24 hours in milliseconds
  refresh-expiration: 604800000  # 7 days in milliseconds
```

### 🔒 Security Configuration
```yaml
security:
  password:
    min-length: 8
    require-uppercase: true
    require-lowercase: true
    require-numbers: true
    require-special-chars: true
  
  account-lockout:
    enabled: true
    max-attempts: 5
    lockout-duration: 900000  # 15 minutes
  
  session:
    timeout: 1800000  # 30 minutes
    concurrent-sessions: 1
```

### 📧 Email Configuration
```yaml
email:
  smtp:
    host: smtp.gmail.com
    port: 587
    username: your-email@gmail.com
    password: your-app-password
    auth: true
    starttls: true
  
  verification:
    enabled: true
    token-expiry: 24  # hours
    from-address: "noreply@yourcompany.com"
    from-name: "Your App Name"
  
  password-reset:
    enabled: true
    token-expiry: 2   # hours
    max-attempts: 3
```

### 🔑 OAuth2 Configuration
```yaml
oauth2:
  google:
    enabled: true
    client-id: "your-google-client-id"
    client-secret: "your-google-client-secret"
    redirect-uri: "http://localhost:8080/oauth2/callback/google"
  
  github:
    enabled: true
    client-id: "your-github-client-id"
    client-secret: "your-github-client-secret"
    redirect-uri: "http://localhost:8080/oauth2/callback/github"
  
  success-url: "http://localhost:3000/dashboard"
  failure-url: "http://localhost:3000/login?error=oauth"
```

### 🛡️ Rate Limiting
```yaml
rate-limiting:
  enabled: true
  login:
    max-attempts: 5
    window-size: 900000  # 15 minutes
  api:
    max-requests: 100
    window-size: 3600000  # 1 hour
```

### 🌐 CORS Configuration
```yaml
cors:
  enabled: true
  allowed-origins:
    - "http://localhost:3000"
    - "https://yourfrontend.com"
  allowed-methods:
    - GET
    - POST
    - PUT
    - DELETE
    - OPTIONS
  allowed-headers:
    - "*"
  allow-credentials: true
  max-age: 3600
```

### 🌍 Environment Configuration
```yaml
environment:
  name: production  # development, testing, production
  debug: false
  frontend-url: "https://yourfrontend.com"
  api-url: "https://yourapi.com"
```

## 🚀 Environment-Specific Configurations

### 🛠️ Development Environment
```yaml
environment:
  name: development
  debug: true

app:
  database:
    type: h2

email:
  smtp:
    host: localhost
    port: 1025

logging:
  level:
    com.auth: DEBUG
```

### 🧪 Testing Environment
```yaml
environment:
  name: testing

app:
  database:
    type: h2

jwt:
  expiration: 3600000  # Shorter expiration for tests

email:
  verification:
    enabled: false  # Skip email verification in tests
```

### 🏭 Production Environment
```yaml
environment:
  name: production
  debug: false

app:
  database:
    type: postgresql
    host: your-db-host
    username: ${DB_USERNAME}
    password: ${DB_PASSWORD}

jwt:
  secret: ${JWT_SECRET}  # Use environment variables for secrets

email:
  smtp:
    host: ${SMTP_HOST}
    username: ${SMTP_USERNAME}
    password: ${SMTP_PASSWORD}

oauth2:
  google:
    client-id: ${GOOGLE_CLIENT_ID}
    client-secret: ${GOOGLE_CLIENT_SECRET}

server:
  ssl:
    enabled: true
    key-store: ${SSL_KEYSTORE_PATH}
    key-store-password: ${SSL_KEYSTORE_PASSWORD}
```

## 🔍 Configuration Management APIs

### View Current Configuration
```bash
# Get configuration summary
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" \
     http://localhost:8080/api/admin/custom-config/summary

# Validate configuration
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" \
     http://localhost:8080/api/admin/custom-config/validate

# Get configuration guide
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" \
     http://localhost:8080/api/admin/custom-config/guide
```

### Check Configuration File Status
```bash
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" \
     http://localhost:8080/api/admin/custom-config/file-status
```

## ⚠️ Security Best Practices

### 1. **Protect Sensitive Information**
```yaml
# ❌ Don't hardcode secrets
jwt:
  secret: "hardcoded-secret-key"

# ✅ Use environment variables
jwt:
  secret: ${JWT_SECRET}
```

### 2. **Use Strong Passwords**
```yaml
# ✅ Strong admin password
admin:
  default-user:
    password: ${ADMIN_PASSWORD}  # Set via environment variable
```

### 3. **Environment-Specific Secrets**
```bash
# Development
export JWT_SECRET="dev-secret-key-for-testing-only"

# Production
export JWT_SECRET="very-long-random-production-secret-key-here"
```

### 4. **File Permissions**
```bash
# Secure the configuration file
chmod 600 app.config.yaml
chown app-user:app-group app.config.yaml
```

## 🔄 Configuration Precedence

The application loads configuration in this order (highest priority first):

1. **Environment Variables** (e.g., `JWT_SECRET`)
2. **app.config.yaml** (custom configuration file)
3. **application.yml** (default Spring Boot configuration)
4. **Built-in defaults**

## 📝 Example Complete Configuration

```yaml
# Complete example app.config.yaml for production
server:
  port: 8080
  ssl:
    enabled: true
    key-store: classpath:keystore.p12
    key-store-password: ${SSL_PASSWORD}

app:
  database:
    type: postgresql
    host: ${DB_HOST}
    port: 5432
    name: authdb_prod
    username: ${DB_USERNAME}
    password: ${DB_PASSWORD}

jwt:
  secret: ${JWT_SECRET}
  expiration: 3600000    # 1 hour for production
  refresh-expiration: 86400000  # 24 hours

security:
  password:
    min-length: 12
    require-uppercase: true
    require-lowercase: true
    require-numbers: true
    require-special-chars: true
  
  account-lockout:
    enabled: true
    max-attempts: 3
    lockout-duration: 1800000  # 30 minutes

email:
  smtp:
    host: ${SMTP_HOST}
    port: 587
    username: ${SMTP_USERNAME}
    password: ${SMTP_PASSWORD}
    auth: true
    starttls: true
  
  verification:
    enabled: true
    token-expiry: 24
    from-address: "noreply@yourcompany.com"
    from-name: "Your Company Auth"

two-factor:
  enabled: true
  issuer: "Your Company"

oauth2:
  google:
    enabled: true
    client-id: ${GOOGLE_CLIENT_ID}
    client-secret: ${GOOGLE_CLIENT_SECRET}
  
  github:
    enabled: true
    client-id: ${GITHUB_CLIENT_ID}
    client-secret: ${GITHUB_CLIENT_SECRET}

rate-limiting:
  enabled: true
  login:
    max-attempts: 3
    window-size: 900000
  api:
    max-requests: 1000
    window-size: 3600000

environment:
  name: production
  debug: false
  frontend-url: "https://app.yourcompany.com"
  api-url: "https://api.yourcompany.com"

admin:
  default-user:
    username: ${ADMIN_USERNAME}
    email: ${ADMIN_EMAIL}
    password: ${ADMIN_PASSWORD}

features:
  registration:
    enabled: true
    require-email-verification: true
    auto-login-after-registration: false
```

## 🆘 Troubleshooting

### Configuration Not Loading
1. Check file location: `app.config.yaml` must be in the application directory
2. Check file permissions: Ensure the application can read the file
3. Check YAML syntax: Use a YAML validator to verify syntax
4. Check application logs for configuration loading messages

### Invalid Configuration
1. Use the validation API: `GET /api/admin/custom-config/validate`
2. Check for typos in property names
3. Ensure data types match (strings, numbers, booleans)
4. Verify required properties are present

### Environment Variables Not Working
1. Ensure environment variables are exported: `export VAR_NAME=value`
2. Use correct syntax in YAML: `${VAR_NAME}`
3. Check variable names are exact matches
4. Restart application after setting environment variables

---

For more help, visit the [Configuration API endpoints](#configuration-management-apis) or check the application logs for detailed error messages.

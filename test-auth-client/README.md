# AuthServerClient (by Kunal Patil)

A Node.js wrapper for the Java-based Authentication Server (JWT, OAuth2, 2FA, Admin, Config, etc.).  
This package allows you to easily integrate authentication, user management, and configuration endpoints into your Node.js apps.

---

## Features

- Full authentication (JWT, OAuth2, 2FA)
- User registration, login, password reset, email verification
- Admin and configuration endpoints
- Reads config from `app.config.yml` (no need to specify port in code)
- Simple, promise-based API

---

## Installation

```bash
npm install auth-server-client
```

---

## Configuration

Place an `app.config.yml` file in your project root (or wherever you want, just provide the path in your code).

---

## app.config.yml Example and Required Fields

The `app.config.yml` file is used to configure the AuthServerClient. Place this file in your project root, or specify its path when initializing the client.

**Minimal required content:**
```yaml
app:
  baseUrl: http://localhost:4554/api  # Java Auth Server API base URL
```

**Full example with optional fields:**
```yaml
app:
  baseUrl: http://localhost:4554/api  # (Required) Java Auth Server API base URL
  # port: 4554                      # (Optional) Port for the Java server (if needed)
  # logLevel: info                   # (Optional) Logging level
  # otherField: value                # (Optional) Any other custom fields
```

- `baseUrl` is required and should point to your running Java Auth Server's API endpoint.
- All other fields are optional and can be omitted unless your setup requires them.
- If you place the config file elsewhere, pass its path to the client:
  ```js
  const wrapper = new AuthWrapper({ configPath: '/path/to/app.config.yml' });
  ```

---

## Sample app.config.yml

Below is a sample `app.config.yml` you can use as a starting point. Copy this to your project and adjust as needed:



## Full Example: Complete app.config.yml

Below is the full contents of a comprehensive `app.config.yml` for the authentication server. This includes all possible fields, comments, and structure. Use this as a reference or starting point—copy, trim, or modify as needed for your project.

```yaml
# ===============================================
# AUTHENTICATION SERVER - MAIN CONFIGURATION
# ===============================================

server:

  port: 4551
  servlet:
    context-path: /
  forward-headers-strategy: framework
  compression:
    enabled: true
    mime-types: text/html,text/xml,text/plain,text/css,text/javascript,application/javascript,application/json
    min-response-size: 1024
  error:
    include-stacktrace: never
    include-message: never

# ===== DATABASE CONFIGURATION =====
# Users can choose between: postgresql, mysql, mongodb, h2
app:
  database:
    type: mysql
    host: localhost
    port: 3306
    name: mydb
    username: kunal
    password: kunal
    
    # Connection pool settings (for SQL databases)
    pool:
      maximum-size: 20
      minimum-idle: 5
      connection-timeout: 30000
      idle-timeout: 600000
      max-lifetime: 1800000
    
    # Additional options
    options:
      create-database-if-not-exist: true
      show-sql: false
      format-sql: false

# ===== SPRING PROFILES =====
spring:
  profiles:
    active: ${SPRING_PROFILES_ACTIVE:development}
  
  # JPA Configuration (will be set dynamically based on database type)
  jpa:
    database-platform: org.hibernate.dialect.MySQL8Dialect
    hibernate:
      ddl-auto: update
      naming:
        physical-strategy: org.hibernate.boot.model.naming.PhysicalNamingStrategyStandardImpl
    show-sql: true
    properties:
      hibernate:
        format_sql: true
        dialect: org.hibernate.dialect.MySQL8Dialect
        jdbc:
          lob:
            non_contextual_creation: true
          batch_size: 25
        order_inserts: true
        order_updates: true

  # Data MongoDB (used when database.type = mongodb)
  data:
    mongodb:
      host: ${app.database.host}
      port: ${app.database.port:27017}
      database: ${app.database.name}
      username: ${app.database.username}
      password: ${app.database.password}
      authentication-database: ${app.database.mongodb.authentication-database}

  # Mail Configuration
  mail:
    host: ${MAIL_HOST:smtp.gmail.com}
    port: ${MAIL_PORT:587}
    username: ${MAIL_USERNAME:kunaldp379@gmail.com}
    password: ${MAIL_PASSWORD:your-app-password}
    properties:
      mail:
        smtp:
          auth: ${MAIL_SMTP_AUTH:true}
          starttls:
            enable: ${MAIL_SMTP_STARTTLS:true}
          ssl:
            trust: ${MAIL_HOST:smtp.gmail.com}
          connectiontimeout: 5000
          timeout: 3000
          writetimeout: 5000

  # Jackson Configuration
  jackson:
    serialization:
      write-dates-as-timestamps: false
      indent-output: false
    time-zone: UTC
    default-property-inclusion: NON_NULL

  # Multipart Configuration
  servlet:
    multipart:
      enabled: true
      max-file-size: ${MAX_FILE_SIZE:2MB}
      max-request-size: ${MAX_REQUEST_SIZE:2MB}

  # OAuth2 Configuration
  security:
    oauth2:
      client:
        registration:
          google:
            client-id: 
            client-secret: 
            scope: profile,email
            redirect-uri: http://localhost:4554/oauth2/callback/google
          github:
            client-id: 
            client-secret: 
            scope: user:email
            redirect-uri: 

  # Cache Configuration
  cache:
    type: simple
    cache-names: configurations,users,roles

# ===== APPLICATION SPECIFIC CONFIGURATION =====
# app:
#   name: ${APP_NAME:Authentication Server}
#   version: ${APP_VERSION:1.0.0}
#   description: ${APP_DESCRIPTION:Complete Authentication Server with JWT, OAuth2, and 2FA}
  frontend-url: ${FRONTEND_URL:http://localhost:3000}
  
  # JWT Configuration
  jwt:
    secret: ${JWT_SECRET:mySecretKey123ForAuthenticationServer2024!@#$%^&*()}
    expiration-ms: ${JWT_EXPIRATION_MS:3600000}
    refresh-expiration-ms: ${JWT_REFRESH_EXPIRATION_MS:604800000}
  
  # Security Configuration
  # security:
  #   password:
  #     min-length: ${PASSWORD_MIN_LENGTH:8}
  #   max-login-attempts: ${MAX_LOGIN_ATTEMPTS:5}
  #   account-lockout-duration: ${LOCKOUT_DURATION:30}
  #   session-timeout: ${SESSION_TIMEOUT:30}
  
  # Two-Factor Authentication
  two-factor:
    issuer-name: ${TFA_ISSUER_NAME:AuthServer}
    window-size: 3
    code-digits: 6
    code-period: 30
    qr-code:
      width: ${TFA_QR_WIDTH:200}
      height: ${TFA_QR_HEIGHT:200}
  
  # CORS Configuration
  cors:
    allowed-origins: ${CORS_ALLOWED_ORIGINS:http://localhost:3000,http://localhost:3001,https://yourdomain.com}
    allowed-methods: GET,POST,PUT,DELETE,OPTIONS
    allowed-headers: "*"
    allow-credentials: true
    max-age: 3600
  
  # Rate Limiting
  rate-limit:
    enabled: ${RATE_LIMIT_ENABLED:true}
    requests-per-minute: ${RATE_LIMIT_RPM:60}
    requests-per-hour: ${RATE_LIMIT_RPH:1000}
  
  # Email Configuration
  email:
    verification:
      token-expiry: ${EMAIL_VERIFICATION_EXPIRY:24}
    password-reset:
      token-expiry: ${PASSWORD_RESET_EXPIRY:2}
    templates:
      path: classpath:/email-templates/
    from:
      name: ${EMAIL_FROM_NAME:Authentication Server}
      address: ${EMAIL_FROM_ADDRESS:noreply@authserver.com}
  
  # Feature Flags
  features:
    oauth2-enabled: ${OAUTH2_ENABLED:true}
    two-factor-enabled: ${TFA_ENABLED:true}
    email-verification-enabled: ${EMAIL_VERIFICATION_ENABLED:true}
    password-reset-enabled: ${PASSWORD_RESET_ENABLED:true}
    user-registration-enabled: ${USER_REGISTRATION_ENABLED:true}
  
  # Business Rules
  user:
    max-sessions: ${MAX_USER_SESSIONS:5}
    password:
      history-count: ${PASSWORD_HISTORY_COUNT:5}
      expiry-days: ${PASSWORD_EXPIRY_DAYS:90}
  
  # Notifications
  notifications:
    email-enabled: ${EMAIL_NOTIFICATIONS_ENABLED:true}
    sms-enabled: ${SMS_NOTIFICATIONS_ENABLED:false}
  
  # API Configuration
  api:
    version:
      header-name: X-API-Version
      default-version: v1

# ===== LOGGING CONFIGURATION =====
logging:
  level:
    com.auth: ${LOG_LEVEL:INFO}
    org.springframework.security: WARN
    org.hibernate.SQL: WARN
    org.hibernate.type.descriptor.sql.BasicBinder: WARN
    org.springframework.web: WARN
  file:
    name: ${LOG_FILE_PATH:logs/authentication-server.log}
    max-size: 10MB
    max-history: 30
  pattern:
    file: "%d{yyyy-MM-dd HH:mm:ss} [%thread] %-5level %logger{36} - %msg%n"
    console: "%d{HH:mm:ss.SSS} [%thread] %-5level %logger{36} - %msg%n"

# ===== ACTUATOR/MONITORING CONFIGURATION =====
management:
  endpoints:
    web:
      exposure:
        include: health,info,metrics,prometheus
  endpoint:
    health:
      show-details: when-authorized
      show-components: when-authorized
  info:
    env:
      enabled: true
  metrics:
    export:
      prometheus:
        enabled: true

# ===== INFO ENDPOINT =====
info:
  app:
    name: ${app.name}
    version: ${app.version}
    description: ${app.description}

```

---

## Usage Example

Here’s a sample Express server using the AuthWrapper:

```js
const express = require('express');
const path = require('path');
const { AuthWrapper } = require('auth-server-client'); // Ensure this is the right module

const resolvedConfigPath = path.resolve(__dirname, 'app.config.yml');

const wrapper = new AuthWrapper({
     port: 4554,
     configPath: resolvedConfigPath
});

const app = express();
const port = 3001;

app.use(express.json());

app.post('/api/login', async (req, res) => {
     try {
          const { usernameOrEmail, password } = req.body;
          const result = await wrapper.login({ usernameOrEmail, password });
          res.json(result);
     } catch (err) {
          res.status(err.response?.status || 500).json(err.response?.data || { error: err.message });
     }
});

app.get('/abc/xyz/health', (req, res) => {
     res.json({ status: 'ok' });
});

(async () => {
     try {
          wrapper.startServerAsync();
          app.listen(port, () => {
               console.log(`✅ Express server running at http://localhost:${port}`);
          });
     } catch (err) {
          console.error('❌ Failed to start servers:', err);
          process.exit(1);
     }
})();

```

---

## Endpoints Documentation

### Authentication

| Endpoint                | Method | Request Body Fields                                 | Description                        |
|-------------------------|--------|-----------------------------------------------------|------------------------------------|
| `/auth/signin`          | POST   | `usernameOrEmail`, `password`, `twoFactorCode?`     | Login (returns JWT, refresh, etc.) |
| `/auth/signup`          | POST   | `username`, `email`, `password`, `firstName`, `lastName`, `roles?` | Register new user                  |
| `/auth/refresh`         | POST   | `refreshToken`                                      | Refresh JWT token                  |
| `/auth/logout`          | POST   | `accessToken` (in header)                           | Logout                             |
| `/auth/verify-email`    | POST   | `token`                                             | Verify email                       |
| `/auth/resend-verification` | POST | `email`                                            | Resend verification email          |
| `/auth/forgot-password` | POST   | `email`                                             | Request password reset             |
| `/auth/reset-password`  | POST   | `token`, `newPassword`                              | Reset password                     |
| `/auth/2fa/setup`       | POST   | `accessToken` (in header)                           | Setup 2FA                          |
| `/auth/2fa/verify`      | POST   | `code`                                              | Verify 2FA code                    |
| `/auth/2fa/disable`     | POST   | `code`, `accessToken` (in header)                   | Disable 2FA                        |

### Admin/User Management

| Endpoint                | Method | Request Body/Params                                 | Description                        |
|-------------------------|--------|-----------------------------------------------------|------------------------------------|
| `/admin/dashboard`      | GET    | `accessToken` (in header)                           | Get admin dashboard                |
| `/admin/users`          | GET    | `accessToken` (in header)                           | Get all users                      |
| `/admin/users/recent`   | GET    | `accessToken` (in header), `limit?`                 | Get recent users                   |
| `/admin/users/enable`   | POST   | `accessToken` (in header), `userId`                 | Enable user                        |
| `/admin/users/disable`  | POST   | `accessToken` (in header), `userId`                 | Disable user                       |
| `/admin/users/delete`   | POST   | `accessToken` (in header), `userId`                 | Delete user                        |
| `/admin/users/2fa/reset`| POST   | `accessToken` (in header), `userId`                 | Reset user 2FA                     |
| `/admin/system/cleanup` | POST   | `accessToken` (in header)                           | System cleanup                     |

### Configuration Management

| Endpoint                        | Method | Request Body/Params                | Description                        |
|----------------------------------|--------|------------------------------------|------------------------------------|
| `/admin/config/all`              | GET    | `accessToken` (in header)          | Get all configurations             |
| `/admin/config/editable`         | GET    | `accessToken` (in header)          | Get editable configurations        |
| `/admin/config`                  | POST   | `accessToken` (in header), `config`| Create configuration               |
| `/admin/config/:key`             | PUT    | `accessToken` (in header), `config`| Update configuration by key        |
| `/admin/config/:key`             | DELETE | `accessToken` (in header)          | Delete configuration by key        |
| `/admin/config/initialize`       | POST   | `accessToken` (in header)          | Initialize default configs         |
| `/admin/config/reset`            | POST   | `accessToken` (in header)          | Reset configs to defaults          |

### System Management

| Endpoint                | Method | Request Body/Params                | Description                        |
|-------------------------|--------|------------------------------------|------------------------------------|
| `/admin/system/reload`  | POST   | `accessToken` (in header)          | Reload config                      |
| `/admin/system/health`  | GET    | `accessToken` (in header)          | System health                      |
| `/admin/system/gc`      | POST   | `accessToken` (in header)          | Force garbage collection           |

### Custom Config Endpoints

| Endpoint                        | Method | Request Body/Params                | Description                        |
|----------------------------------|--------|------------------------------------|------------------------------------|
| `/admin/custom-config/summary`   | GET    | `accessToken` (in header)          | Get custom config summary          |
| `/admin/custom-config/validate`  | POST   | `accessToken` (in header)          | Validate custom config             |
| `/admin/custom-config/guide`     | GET    | `accessToken` (in header)          | Get custom config guide            |
| `/admin/custom-config/env-recommendations` | GET | `accessToken` (in header)         | Get environment recommendations    |
| `/admin/custom-config/file-status`| GET   | `accessToken` (in header)          | Get config file status             |

### Test & Health Endpoints

| Endpoint                | Method | Request Body/Params                | Description                        |
|-------------------------|--------|------------------------------------|------------------------------------|
| `/test/all`             | GET    |                                    | Test all endpoints                 |
| `/test/user`            | GET    | `accessToken` (in header)          | Test user endpoint                 |
| `/test/mod`             | GET    | `accessToken` (in header)          | Test moderator endpoint            |
| `/test/admin`           | GET    | `accessToken` (in header)          | Test admin endpoint                |
| `/health`               | GET    |                                    | Health check                       |

---

## Request Types

- **POST**: Used for creating resources, login, registration, etc.
- **GET**: Used for fetching data (users, configs, health, etc.).
- **PUT**: Used for updating resources (e.g., configuration by key).
- **DELETE**: Used for deleting resources.

---

## Required Fields

- For authentication endpoints, see the "Request Body Fields" column above.
- For admin/config endpoints, always provide a valid `accessToken` in the `Authorization` header:  
  `Authorization: Bearer <your-jwt-access-token>`

---

## Where to Place `app.config.yml`

- Place it in your project root (or any directory).
- Pass its path to the wrapper/client:
  ```js
  const wrapper = new AuthWrapper({ configPath: '/path/to/app.config.yml' });
  ```
- The config file should contain at least:
  ```yaml
  app:
    baseUrl: http://localhost:4554/api
  ```
  You can add more fields as needed.

---

## Error Handling

All methods return promises. Catch errors as follows:

```js
client.login({ ... })
  .then(data => ...)
  .catch(err => {
    // err.response?.data for server error message
    console.error(err);
  });
```

---

## Troubleshooting

- Ensure your Java server is running and accessible at the configured `baseUrl`.
- If you get connection errors, check your network and CORS settings.
- For protected endpoints, always provide a valid `accessToken` (JWT).
- If you change the config file, restart your Node.js process to reload it.

---

## License

MIT 
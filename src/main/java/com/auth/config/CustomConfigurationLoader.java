package com.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;

import jakarta.annotation.PostConstruct;
import java.io.File;
import java.util.List;

/**
 * Custom configuration loader that reads from app.config.yaml
 * This allows users to provide custom configurations that override defaults
 */
@Component
@Configuration
@ConfigurationProperties(prefix = "")
public class CustomConfigurationLoader {

    // Server configuration
    private ServerConfig server = new ServerConfig();
    
    // Database configuration  
    private AppConfig app = new AppConfig();
    
    // JWT configuration
    private JwtConfig jwt = new JwtConfig();
    
    // Security configuration
    private SecurityConfig security = new SecurityConfig();
    
    // Email configuration
    private EmailConfig email = new EmailConfig();
    
    // Two-factor authentication
    private TwoFactorConfig twoFactor = new TwoFactorConfig();
    
    // OAuth2 configuration
    private OAuth2Config oauth2 = new OAuth2Config();
    
    // Rate limiting
    private RateLimitingConfig rateLimiting = new RateLimitingConfig();
    
    // CORS configuration
    private CorsConfig cors = new CorsConfig();
    
    // Environment configuration
    private EnvironmentConfig environment = new EnvironmentConfig();

    @PostConstruct
    public void init() {
        loadCustomConfiguration();
    }

    private void loadCustomConfiguration() {
        // Check if app.config.yaml exists in the application directory
        File configFile = new File("app.config.yaml");
        if (configFile.exists()) {
            System.out.println("✅ Loading custom configuration from app.config.yaml");
            // Custom configuration loading logic will be implemented here
        } else {
            System.out.println("ℹ️ Using default configuration (app.config.yaml not found)");
        }
    }

    // Getters and Setters for all configuration classes
    public ServerConfig getServer() { return server; }
    public void setServer(ServerConfig server) { this.server = server; }
    
    public AppConfig getApp() { return app; }
    public void setApp(AppConfig app) { this.app = app; }
    
    public JwtConfig getJwt() { return jwt; }
    public void setJwt(JwtConfig jwt) { this.jwt = jwt; }
    
    public SecurityConfig getSecurity() { return security; }
    public void setSecurity(SecurityConfig security) { this.security = security; }
    
    public EmailConfig getEmail() { return email; }
    public void setEmail(EmailConfig email) { this.email = email; }
    
    public TwoFactorConfig getTwoFactor() { return twoFactor; }
    public void setTwoFactor(TwoFactorConfig twoFactor) { this.twoFactor = twoFactor; }
    
    public OAuth2Config getOauth2() { return oauth2; }
    public void setOauth2(OAuth2Config oauth2) { this.oauth2 = oauth2; }
    
    public RateLimitingConfig getRateLimiting() { return rateLimiting; }
    public void setRateLimiting(RateLimitingConfig rateLimiting) { this.rateLimiting = rateLimiting; }
    
    public CorsConfig getCors() { return cors; }
    public void setCors(CorsConfig cors) { this.cors = cors; }
    
    public EnvironmentConfig getEnvironment() { return environment; }
    public void setEnvironment(EnvironmentConfig environment) { this.environment = environment; }

    // Inner configuration classes
    public static class ServerConfig {
        private int port = 4554;
        private ServletConfig servlet = new ServletConfig();
        private SslConfig ssl = new SslConfig();

        // Getters and setters
        public int getPort() { return port; }
        public void setPort(int port) { this.port = port; }
        public ServletConfig getServlet() { return servlet; }
        public void setServlet(ServletConfig servlet) { this.servlet = servlet; }
        public SslConfig getSsl() { return ssl; }
        public void setSsl(SslConfig ssl) { this.ssl = ssl; }

        public static class ServletConfig {
            private String contextPath = "/";
            public String getContextPath() { return contextPath; }
            public void setContextPath(String contextPath) { this.contextPath = contextPath; }
        }

        public static class SslConfig {
            private boolean enabled = false;
            private String keyStore;
            private String keyStorePassword;
            private String keyStoreType = "PKCS12";
            
            // Getters and setters
            public boolean isEnabled() { return enabled; }
            public void setEnabled(boolean enabled) { this.enabled = enabled; }
            public String getKeyStore() { return keyStore; }
            public void setKeyStore(String keyStore) { this.keyStore = keyStore; }
            public String getKeyStorePassword() { return keyStorePassword; }
            public void setKeyStorePassword(String keyStorePassword) { this.keyStorePassword = keyStorePassword; }
            public String getKeyStoreType() { return keyStoreType; }
            public void setKeyStoreType(String keyStoreType) { this.keyStoreType = keyStoreType; }
        }
    }

    public static class AppConfig {
        private DatabaseConfig database = new DatabaseConfig();
        
        public DatabaseConfig getDatabase() { return database; }
        public void setDatabase(DatabaseConfig database) { this.database = database; }

        public static class DatabaseConfig {
            private String type = "h2";
            private String host = "localhost";
            private Integer port;
            private String name = "authdb";
            private String username = "sa";
            private String password = "";
            private PoolConfig pool = new PoolConfig();

            // Getters and setters
            public String getType() { return type; }
            public void setType(String type) { this.type = type; }
            public String getHost() { return host; }
            public void setHost(String host) { this.host = host; }
            public Integer getPort() { return port; }
            public void setPort(Integer port) { this.port = port; }
            public String getName() { return name; }
            public void setName(String name) { this.name = name; }
            public String getUsername() { return username; }
            public void setUsername(String username) { this.username = username; }
            public String getPassword() { return password; }
            public void setPassword(String password) { this.password = password; }
            public PoolConfig getPool() { return pool; }
            public void setPool(PoolConfig pool) { this.pool = pool; }

            public static class PoolConfig {
                private int maximumSize = 20;
                private int minimumIdle = 5;
                private long connectionTimeout = 30000;
                private long idleTimeout = 600000;
                private long maxLifetime = 1800000;

                // Getters and setters
                public int getMaximumSize() { return maximumSize; }
                public void setMaximumSize(int maximumSize) { this.maximumSize = maximumSize; }
                public int getMinimumIdle() { return minimumIdle; }
                public void setMinimumIdle(int minimumIdle) { this.minimumIdle = minimumIdle; }
                public long getConnectionTimeout() { return connectionTimeout; }
                public void setConnectionTimeout(long connectionTimeout) { this.connectionTimeout = connectionTimeout; }
                public long getIdleTimeout() { return idleTimeout; }
                public void setIdleTimeout(long idleTimeout) { this.idleTimeout = idleTimeout; }
                public long getMaxLifetime() { return maxLifetime; }
                public void setMaxLifetime(long maxLifetime) { this.maxLifetime = maxLifetime; }
            }
        }
    }

    public static class JwtConfig {
        private String secret = "mySecretKey123ForAuthenticationServerDevelopment2024!@#";
        private long expiration = 86400000; // 24 hours
        private long refreshExpiration = 604800000; // 7 days

        // Getters and setters
        public String getSecret() { return secret; }
        public void setSecret(String secret) { this.secret = secret; }
        public long getExpiration() { return expiration; }
        public void setExpiration(long expiration) { this.expiration = expiration; }
        public long getRefreshExpiration() { return refreshExpiration; }
        public void setRefreshExpiration(long refreshExpiration) { this.refreshExpiration = refreshExpiration; }
    }

    public static class SecurityConfig {
        private PasswordConfig password = new PasswordConfig();
        private AccountLockoutConfig accountLockout = new AccountLockoutConfig();
        private SessionConfig session = new SessionConfig();

        // Getters and setters
        public PasswordConfig getPassword() { return password; }
        public void setPassword(PasswordConfig password) { this.password = password; }
        public AccountLockoutConfig getAccountLockout() { return accountLockout; }
        public void setAccountLockout(AccountLockoutConfig accountLockout) { this.accountLockout = accountLockout; }
        public SessionConfig getSession() { return session; }
        public void setSession(SessionConfig session) { this.session = session; }

        public static class PasswordConfig {
            private int minLength = 8;
            private boolean requireUppercase = true;
            private boolean requireLowercase = true;
            private boolean requireNumbers = true;
            private boolean requireSpecialChars = true;

            // Getters and setters
            public int getMinLength() { return minLength; }
            public void setMinLength(int minLength) { this.minLength = minLength; }
            public boolean isRequireUppercase() { return requireUppercase; }
            public void setRequireUppercase(boolean requireUppercase) { this.requireUppercase = requireUppercase; }
            public boolean isRequireLowercase() { return requireLowercase; }
            public void setRequireLowercase(boolean requireLowercase) { this.requireLowercase = requireLowercase; }
            public boolean isRequireNumbers() { return requireNumbers; }
            public void setRequireNumbers(boolean requireNumbers) { this.requireNumbers = requireNumbers; }
            public boolean isRequireSpecialChars() { return requireSpecialChars; }
            public void setRequireSpecialChars(boolean requireSpecialChars) { this.requireSpecialChars = requireSpecialChars; }
        }

        public static class AccountLockoutConfig {
            private boolean enabled = true;
            private int maxAttempts = 5;
            private long lockoutDuration = 900000; // 15 minutes

            // Getters and setters
            public boolean isEnabled() { return enabled; }
            public void setEnabled(boolean enabled) { this.enabled = enabled; }
            public int getMaxAttempts() { return maxAttempts; }
            public void setMaxAttempts(int maxAttempts) { this.maxAttempts = maxAttempts; }
            public long getLockoutDuration() { return lockoutDuration; }
            public void setLockoutDuration(long lockoutDuration) { this.lockoutDuration = lockoutDuration; }
        }

        public static class SessionConfig {
            private long timeout = 1800000; // 30 minutes
            private int concurrentSessions = 1;

            // Getters and setters
            public long getTimeout() { return timeout; }
            public void setTimeout(long timeout) { this.timeout = timeout; }
            public int getConcurrentSessions() { return concurrentSessions; }
            public void setConcurrentSessions(int concurrentSessions) { this.concurrentSessions = concurrentSessions; }
        }
    }

    public static class EmailConfig {
        private SmtpConfig smtp = new SmtpConfig();
        private VerificationConfig verification = new VerificationConfig();
        private PasswordResetConfig passwordReset = new PasswordResetConfig();

        // Getters and setters
        public SmtpConfig getSmtp() { return smtp; }
        public void setSmtp(SmtpConfig smtp) { this.smtp = smtp; }
        public VerificationConfig getVerification() { return verification; }
        public void setVerification(VerificationConfig verification) { this.verification = verification; }
        public PasswordResetConfig getPasswordReset() { return passwordReset; }
        public void setPasswordReset(PasswordResetConfig passwordReset) { this.passwordReset = passwordReset; }

        public static class SmtpConfig {
            private String host = "localhost";
            private int port = 587;
            private String username = "";
            private String password = "";
            private boolean auth = true;
            private boolean starttls = true;

            // Getters and setters
            public String getHost() { return host; }
            public void setHost(String host) { this.host = host; }
            public int getPort() { return port; }
            public void setPort(int port) { this.port = port; }
            public String getUsername() { return username; }
            public void setUsername(String username) { this.username = username; }
            public String getPassword() { return password; }
            public void setPassword(String password) { this.password = password; }
            public boolean isAuth() { return auth; }
            public void setAuth(boolean auth) { this.auth = auth; }
            public boolean isStarttls() { return starttls; }
            public void setStarttls(boolean starttls) { this.starttls = starttls; }
        }

        public static class VerificationConfig {
            private boolean enabled = true;
            private int tokenExpiry = 24; // hours
            private String fromAddress = "noreply@authserver.com";
            private String fromName = "Authentication Server";

            // Getters and setters
            public boolean isEnabled() { return enabled; }
            public void setEnabled(boolean enabled) { this.enabled = enabled; }
            public int getTokenExpiry() { return tokenExpiry; }
            public void setTokenExpiry(int tokenExpiry) { this.tokenExpiry = tokenExpiry; }
            public String getFromAddress() { return fromAddress; }
            public void setFromAddress(String fromAddress) { this.fromAddress = fromAddress; }
            public String getFromName() { return fromName; }
            public void setFromName(String fromName) { this.fromName = fromName; }
        }

        public static class PasswordResetConfig {
            private boolean enabled = true;
            private int tokenExpiry = 2; // hours
            private int maxAttempts = 3;

            // Getters and setters
            public boolean isEnabled() { return enabled; }
            public void setEnabled(boolean enabled) { this.enabled = enabled; }
            public int getTokenExpiry() { return tokenExpiry; }
            public void setTokenExpiry(int tokenExpiry) { this.tokenExpiry = tokenExpiry; }
            public int getMaxAttempts() { return maxAttempts; }
            public void setMaxAttempts(int maxAttempts) { this.maxAttempts = maxAttempts; }
        }
    }

    public static class TwoFactorConfig {
        private boolean enabled = true;
        private String issuer = "Authentication Server";
        private QrCodeConfig qrCode = new QrCodeConfig();

        // Getters and setters
        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public String getIssuer() { return issuer; }
        public void setIssuer(String issuer) { this.issuer = issuer; }
        public QrCodeConfig getQrCode() { return qrCode; }
        public void setQrCode(QrCodeConfig qrCode) { this.qrCode = qrCode; }

        public static class QrCodeConfig {
            private int width = 200;
            private int height = 200;

            // Getters and setters
            public int getWidth() { return width; }
            public void setWidth(int width) { this.width = width; }
            public int getHeight() { return height; }
            public void setHeight(int height) { this.height = height; }
        }
    }

    public static class OAuth2Config {
        private GoogleConfig google = new GoogleConfig();
        private GitHubConfig github = new GitHubConfig();
        private String successUrl = "http://localhost:3000/oauth2/redirect";
        private String failureUrl = "http://localhost:3000/oauth2/redirect?error=true";

        // Getters and setters
        public GoogleConfig getGoogle() { return google; }
        public void setGoogle(GoogleConfig google) { this.google = google; }
        public GitHubConfig getGithub() { return github; }
        public void setGithub(GitHubConfig github) { this.github = github; }
        public String getSuccessUrl() { return successUrl; }
        public void setSuccessUrl(String successUrl) { this.successUrl = successUrl; }
        public String getFailureUrl() { return failureUrl; }
        public void setFailureUrl(String failureUrl) { this.failureUrl = failureUrl; }

        public static class GoogleConfig {
            private boolean enabled = false;
            private String clientId;
            private String clientSecret;
            private String redirectUri = "http://localhost:4554/oauth2/callback/google";

            // Getters and setters
            public boolean isEnabled() { return enabled; }
            public void setEnabled(boolean enabled) { this.enabled = enabled; }
            public String getClientId() { return clientId; }
            public void setClientId(String clientId) { this.clientId = clientId; }
            public String getClientSecret() { return clientSecret; }
            public void setClientSecret(String clientSecret) { this.clientSecret = clientSecret; }
            public String getRedirectUri() { return redirectUri; }
            public void setRedirectUri(String redirectUri) { this.redirectUri = redirectUri; }
        }

        public static class GitHubConfig {
            private boolean enabled = false;
            private String clientId;
            private String clientSecret;
            private String redirectUri = "http://localhost:4554/oauth2/callback/github";

            // Getters and setters
            public boolean isEnabled() { return enabled; }
            public void setEnabled(boolean enabled) { this.enabled = enabled; }
            public String getClientId() { return clientId; }
            public void setClientId(String clientId) { this.clientId = clientId; }
            public String getClientSecret() { return clientSecret; }
            public void setClientSecret(String clientSecret) { this.clientSecret = clientSecret; }
            public String getRedirectUri() { return redirectUri; }
            public void setRedirectUri(String redirectUri) { this.redirectUri = redirectUri; }
        }
    }

    public static class RateLimitingConfig {
        private boolean enabled = true;
        private LoginConfig login = new LoginConfig();
        private ApiConfig api = new ApiConfig();

        // Getters and setters
        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public LoginConfig getLogin() { return login; }
        public void setLogin(LoginConfig login) { this.login = login; }
        public ApiConfig getApi() { return api; }
        public void setApi(ApiConfig api) { this.api = api; }

        public static class LoginConfig {
            private int maxAttempts = 5;
            private long windowSize = 900000; // 15 minutes

            // Getters and setters
            public int getMaxAttempts() { return maxAttempts; }
            public void setMaxAttempts(int maxAttempts) { this.maxAttempts = maxAttempts; }
            public long getWindowSize() { return windowSize; }
            public void setWindowSize(long windowSize) { this.windowSize = windowSize; }
        }

        public static class ApiConfig {
            private int maxRequests = 100;
            private long windowSize = 3600000; // 1 hour

            // Getters and setters
            public int getMaxRequests() { return maxRequests; }
            public void setMaxRequests(int maxRequests) { this.maxRequests = maxRequests; }
            public long getWindowSize() { return windowSize; }
            public void setWindowSize(long windowSize) { this.windowSize = windowSize; }
        }
    }

    public static class CorsConfig {
        private boolean enabled = true;
        private List<String> allowedOrigins = List.of("http://localhost:3000", "http://localhost:3001");
        private List<String> allowedMethods = List.of("GET", "POST", "PUT", "DELETE", "OPTIONS");
        private List<String> allowedHeaders = List.of("*");
        private boolean allowCredentials = true;
        private long maxAge = 3600;

        // Getters and setters
        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public List<String> getAllowedOrigins() { return allowedOrigins; }
        public void setAllowedOrigins(List<String> allowedOrigins) { this.allowedOrigins = allowedOrigins; }
        public List<String> getAllowedMethods() { return allowedMethods; }
        public void setAllowedMethods(List<String> allowedMethods) { this.allowedMethods = allowedMethods; }
        public List<String> getAllowedHeaders() { return allowedHeaders; }
        public void setAllowedHeaders(List<String> allowedHeaders) { this.allowedHeaders = allowedHeaders; }
        public boolean isAllowCredentials() { return allowCredentials; }
        public void setAllowCredentials(boolean allowCredentials) { this.allowCredentials = allowCredentials; }
        public long getMaxAge() { return maxAge; }
        public void setMaxAge(long maxAge) { this.maxAge = maxAge; }
    }

    public static class EnvironmentConfig {
        private String name = "development";
        private boolean debug = true;
        private String frontendUrl = "http://localhost:3000";
        private String apiUrl = "http://localhost:4554";

        // Getters and setters
        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
        public boolean isDebug() { return debug; }
        public void setDebug(boolean debug) { this.debug = debug; }
        public String getFrontendUrl() { return frontendUrl; }
        public void setFrontendUrl(String frontendUrl) { this.frontendUrl = frontendUrl; }
        public String getApiUrl() { return apiUrl; }
        public void setApiUrl(String apiUrl) { this.apiUrl = apiUrl; }
    }
}

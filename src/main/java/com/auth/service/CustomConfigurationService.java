package com.auth.service;

import com.auth.config.CustomConfigurationLoader;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * Service to access custom configuration values from app.config.yaml
 * This service provides a convenient way to access configuration values
 * that can be overridden by users in their custom configuration file.
 */
@Service
public class CustomConfigurationService {

    @Autowired
    private CustomConfigurationLoader customConfig;

    // Server Configuration
    @Value("${server.port:4554}")
    private int serverPort;

    // Database Configuration
    @Value("${app.database.type:h2}")
    private String databaseType;

    @Value("${app.database.host:localhost}")
    private String databaseHost;

    @Value("${app.database.name:authdb}")
    private String databaseName;

    @Value("${app.database.username:sa}")
    private String databaseUsername;

    @Value("${app.database.password:}")
    private String databasePassword;

    // JWT Configuration
    @Value("${jwt.secret:mySecretKey123ForAuthenticationServerDevelopment2024!@#}")
    private String jwtSecret;

    @Value("${jwt.expiration:86400000}")
    private long jwtExpiration;

    @Value("${jwt.refresh-expiration:604800000}")
    private long jwtRefreshExpiration;

    // Security Configuration
    @Value("${security.password.min-length:8}")
    private int passwordMinLength;

    @Value("${security.password.require-uppercase:true}")
    private boolean passwordRequireUppercase;

    @Value("${security.password.require-lowercase:true}")
    private boolean passwordRequireLowercase;

    @Value("${security.password.require-numbers:true}")
    private boolean passwordRequireNumbers;

    @Value("${security.password.require-special-chars:true}")
    private boolean passwordRequireSpecialChars;

    @Value("${security.account-lockout.enabled:true}")
    private boolean accountLockoutEnabled;

    @Value("${security.account-lockout.max-attempts:5}")
    private int accountLockoutMaxAttempts;

    @Value("${security.account-lockout.lockout-duration:900000}")
    private long accountLockoutDuration;

    // Email Configuration
    @Value("${email.smtp.host:localhost}")
    private String emailSmtpHost;

    @Value("${email.smtp.port:587}")
    private int emailSmtpPort;

    @Value("${email.smtp.username:}")
    private String emailSmtpUsername;

    @Value("${email.smtp.password:}")
    private String emailSmtpPassword;

    @Value("${email.smtp.auth:true}")
    private boolean emailSmtpAuth;

    @Value("${email.smtp.starttls:true}")
    private boolean emailSmtpStarttls;

    @Value("${email.verification.enabled:true}")
    private boolean emailVerificationEnabled;

    @Value("${email.verification.token-expiry:24}")
    private int emailVerificationTokenExpiry;

    @Value("${email.verification.from-address:noreply@authserver.com}")
    private String emailVerificationFromAddress;

    @Value("${email.verification.from-name:Authentication Server}")
    private String emailVerificationFromName;

    // Two-Factor Authentication
    @Value("${two-factor.enabled:true}")
    private boolean twoFactorEnabled;

    @Value("${two-factor.issuer:Authentication Server}")
    private String twoFactorIssuer;

    @Value("${two-factor.qr-code.width:200}")
    private int twoFactorQrCodeWidth;

    @Value("${two-factor.qr-code.height:200}")
    private int twoFactorQrCodeHeight;

    // OAuth2 Configuration
    @Value("${oauth2.google.enabled:false}")
    private boolean oauth2GoogleEnabled;

    @Value("${oauth2.google.client-id:}")
    private String oauth2GoogleClientId;

    @Value("${oauth2.google.client-secret:}")
    private String oauth2GoogleClientSecret;

    @Value("${oauth2.github.enabled:false}")
    private boolean oauth2GitHubEnabled;

    @Value("${oauth2.github.client-id:}")
    private String oauth2GitHubClientId;

    @Value("${oauth2.github.client-secret:}")
    private String oauth2GitHubClientSecret;

    @Value("${oauth2.success-url:http://localhost:3000/oauth2/redirect}")
    private String oauth2SuccessUrl;

    @Value("${oauth2.failure-url:http://localhost:3000/oauth2/redirect?error=true}")
    private String oauth2FailureUrl;

    // Rate Limiting
    @Value("${rate-limiting.enabled:true}")
    private boolean rateLimitingEnabled;

    @Value("${rate-limiting.login.max-attempts:5}")
    private int rateLimitingLoginMaxAttempts;

    @Value("${rate-limiting.login.window-size:900000}")
    private long rateLimitingLoginWindowSize;

    @Value("${rate-limiting.api.max-requests:100}")
    private int rateLimitingApiMaxRequests;

    @Value("${rate-limiting.api.window-size:3600000}")
    private long rateLimitingApiWindowSize;

    // Environment Configuration
    @Value("${environment.name:development}")
    private String environmentName;

    @Value("${environment.debug:true}")
    private boolean environmentDebug;

    @Value("${environment.frontend-url:http://localhost:3000}")
    private String environmentFrontendUrl;

    @Value("${environment.api-url:http://localhost:4554}")
    private String environmentApiUrl;

    // Admin Configuration
    @Value("${admin.default-user.username:admin}")
    private String adminDefaultUsername;

    @Value("${admin.default-user.email:admin@authserver.com}")
    private String adminDefaultEmail;

    @Value("${admin.default-user.password:admin123}")
    private String adminDefaultPassword;

    @Value("${admin.default-user.create-if-not-exists:true}")
    private boolean adminDefaultUserCreateIfNotExists;

    // Features Configuration
    @Value("${features.registration.enabled:true}")
    private boolean registrationEnabled;

    @Value("${features.registration.require-email-verification:true}")
    private boolean registrationRequireEmailVerification;

    @Value("${features.registration.auto-login-after-registration:false}")
    private boolean registrationAutoLoginAfterRegistration;

    // Getter methods for accessing configuration values

    // Server Configuration
    public int getServerPort() { return serverPort; }

    // Database Configuration
    public String getDatabaseType() { return databaseType; }
    public String getDatabaseHost() { return databaseHost; }
    public String getDatabaseName() { return databaseName; }
    public String getDatabaseUsername() { return databaseUsername; }
    public String getDatabasePassword() { return databasePassword; }

    // JWT Configuration
    public String getJwtSecret() { return jwtSecret; }
    public long getJwtExpiration() { return jwtExpiration; }
    public long getJwtRefreshExpiration() { return jwtRefreshExpiration; }

    // Security Configuration
    public int getPasswordMinLength() { return passwordMinLength; }
    public boolean isPasswordRequireUppercase() { return passwordRequireUppercase; }
    public boolean isPasswordRequireLowercase() { return passwordRequireLowercase; }
    public boolean isPasswordRequireNumbers() { return passwordRequireNumbers; }
    public boolean isPasswordRequireSpecialChars() { return passwordRequireSpecialChars; }
    public boolean isAccountLockoutEnabled() { return accountLockoutEnabled; }
    public int getAccountLockoutMaxAttempts() { return accountLockoutMaxAttempts; }
    public long getAccountLockoutDuration() { return accountLockoutDuration; }

    // Email Configuration
    public String getEmailSmtpHost() { return emailSmtpHost; }
    public int getEmailSmtpPort() { return emailSmtpPort; }
    public String getEmailSmtpUsername() { return emailSmtpUsername; }
    public String getEmailSmtpPassword() { return emailSmtpPassword; }
    public boolean isEmailSmtpAuth() { return emailSmtpAuth; }
    public boolean isEmailSmtpStarttls() { return emailSmtpStarttls; }
    public boolean isEmailVerificationEnabled() { return emailVerificationEnabled; }
    public int getEmailVerificationTokenExpiry() { return emailVerificationTokenExpiry; }
    public String getEmailVerificationFromAddress() { return emailVerificationFromAddress; }
    public String getEmailVerificationFromName() { return emailVerificationFromName; }

    // Two-Factor Authentication
    public boolean isTwoFactorEnabled() { return twoFactorEnabled; }
    public String getTwoFactorIssuer() { return twoFactorIssuer; }
    public int getTwoFactorQrCodeWidth() { return twoFactorQrCodeWidth; }
    public int getTwoFactorQrCodeHeight() { return twoFactorQrCodeHeight; }

    // OAuth2 Configuration
    public boolean isOauth2GoogleEnabled() { return oauth2GoogleEnabled; }
    public String getOauth2GoogleClientId() { return oauth2GoogleClientId; }
    public String getOauth2GoogleClientSecret() { return oauth2GoogleClientSecret; }
    public boolean isOauth2GitHubEnabled() { return oauth2GitHubEnabled; }
    public String getOauth2GitHubClientId() { return oauth2GitHubClientId; }
    public String getOauth2GitHubClientSecret() { return oauth2GitHubClientSecret; }
    public String getOauth2SuccessUrl() { return oauth2SuccessUrl; }
    public String getOauth2FailureUrl() { return oauth2FailureUrl; }

    // Rate Limiting
    public boolean isRateLimitingEnabled() { return rateLimitingEnabled; }
    public int getRateLimitingLoginMaxAttempts() { return rateLimitingLoginMaxAttempts; }
    public long getRateLimitingLoginWindowSize() { return rateLimitingLoginWindowSize; }
    public int getRateLimitingApiMaxRequests() { return rateLimitingApiMaxRequests; }
    public long getRateLimitingApiWindowSize() { return rateLimitingApiWindowSize; }

    // Environment Configuration
    public String getEnvironmentName() { return environmentName; }
    public boolean isEnvironmentDebug() { return environmentDebug; }
    public String getEnvironmentFrontendUrl() { return environmentFrontendUrl; }
    public String getEnvironmentApiUrl() { return environmentApiUrl; }

    // Admin Configuration
    public String getAdminDefaultUsername() { return adminDefaultUsername; }
    public String getAdminDefaultEmail() { return adminDefaultEmail; }
    public String getAdminDefaultPassword() { return adminDefaultPassword; }
    public boolean isAdminDefaultUserCreateIfNotExists() { return adminDefaultUserCreateIfNotExists; }

    // Features Configuration
    public boolean isRegistrationEnabled() { return registrationEnabled; }
    public boolean isRegistrationRequireEmailVerification() { return registrationRequireEmailVerification; }
    public boolean isRegistrationAutoLoginAfterRegistration() { return registrationAutoLoginAfterRegistration; }

    // Utility methods
    public boolean isProductionEnvironment() {
        return "production".equalsIgnoreCase(environmentName);
    }

    public boolean isDevelopmentEnvironment() {
        return "development".equalsIgnoreCase(environmentName);
    }

    public boolean isTestingEnvironment() {
        return "testing".equalsIgnoreCase(environmentName);
    }

    /**
     * Get configuration summary for logging/debugging
     */
    public String getConfigurationSummary() {
        StringBuilder summary = new StringBuilder();
        summary.append("Custom Configuration Summary:\n");
        summary.append("- Environment: ").append(environmentName).append("\n");
        summary.append("- Server Port: ").append(serverPort).append("\n");
        summary.append("- Database Type: ").append(databaseType).append("\n");
        summary.append("- JWT Expiration: ").append(jwtExpiration / 3600000).append(" hours\n");
        summary.append("- 2FA Enabled: ").append(twoFactorEnabled).append("\n");
        summary.append("- Email Verification: ").append(emailVerificationEnabled).append("\n");
        summary.append("- Registration Enabled: ").append(registrationEnabled).append("\n");
        summary.append("- Rate Limiting: ").append(rateLimitingEnabled).append("\n");
        summary.append("- Google OAuth2: ").append(oauth2GoogleEnabled).append("\n");
        summary.append("- GitHub OAuth2: ").append(oauth2GitHubEnabled).append("\n");
        return summary.toString();
    }

    /**
     * Validate current configuration
     */
    public boolean validateConfiguration() {
        boolean isValid = true;
        
        if (jwtSecret.length() < 32) {
            System.err.println("⚠️ JWT secret should be at least 32 characters long");
            isValid = false;
        }
        
        if (isProductionEnvironment() && "admin123".equals(adminDefaultPassword)) {
            System.err.println("⚠️ Default admin password should be changed in production");
            isValid = false;
        }
        
        if (oauth2GoogleEnabled && (oauth2GoogleClientId.isEmpty() || oauth2GoogleClientSecret.isEmpty())) {
            System.err.println("⚠️ Google OAuth2 is enabled but client ID/secret is missing");
            isValid = false;
        }
        
        if (oauth2GitHubEnabled && (oauth2GitHubClientId.isEmpty() || oauth2GitHubClientSecret.isEmpty())) {
            System.err.println("⚠️ GitHub OAuth2 is enabled but client ID/secret is missing");
            isValid = false;
        }
        
        return isValid;
    }
}

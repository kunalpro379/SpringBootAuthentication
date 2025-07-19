package com.auth.controller;

import com.auth.service.CustomConfigurationService;
import com.auth.dto.MessageResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

/**
 * Controller for managing custom configuration
 * Allows administrators to view current configuration status
 */
@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/admin/custom-config")
@PreAuthorize("hasRole('ADMIN')")
public class CustomConfigurationController {

    @Autowired
    private CustomConfigurationService customConfigService;

    /**
     * Get current configuration summary
     */
    @GetMapping("/summary")
    public ResponseEntity<Map<String, Object>> getConfigurationSummary() {
        Map<String, Object> summary = new HashMap<>();
        
        // Server info
        summary.put("server", Map.of(
            "port", customConfigService.getServerPort()
        ));
        
        // Database info (without sensitive data)
        summary.put("database", Map.of(
            "type", customConfigService.getDatabaseType(),
            "host", customConfigService.getDatabaseHost(),
            "name", customConfigService.getDatabaseName(),
            "username", customConfigService.getDatabaseUsername()
        ));
        
        // JWT info (without secret)
        summary.put("jwt", Map.of(
            "expiration_hours", customConfigService.getJwtExpiration() / 3600000,
            "refresh_expiration_hours", customConfigService.getJwtRefreshExpiration() / 3600000
        ));
        
        // Security info
        summary.put("security", Map.of(
            "password_min_length", customConfigService.getPasswordMinLength(),
            "require_uppercase", customConfigService.isPasswordRequireUppercase(),
            "require_lowercase", customConfigService.isPasswordRequireLowercase(),
            "require_numbers", customConfigService.isPasswordRequireNumbers(),
            "require_special_chars", customConfigService.isPasswordRequireSpecialChars(),
            "account_lockout_enabled", customConfigService.isAccountLockoutEnabled(),
            "max_lockout_attempts", customConfigService.getAccountLockoutMaxAttempts()
        ));
        
        // Email info (without credentials)
        summary.put("email", Map.of(
            "smtp_host", customConfigService.getEmailSmtpHost(),
            "smtp_port", customConfigService.getEmailSmtpPort(),
            "verification_enabled", customConfigService.isEmailVerificationEnabled(),
            "verification_token_expiry_hours", customConfigService.getEmailVerificationTokenExpiry(),
            "from_address", customConfigService.getEmailVerificationFromAddress()
        ));
        
        // Two-factor authentication
        summary.put("two_factor", Map.of(
            "enabled", customConfigService.isTwoFactorEnabled(),
            "issuer", customConfigService.getTwoFactorIssuer(),
            "qr_code_width", customConfigService.getTwoFactorQrCodeWidth(),
            "qr_code_height", customConfigService.getTwoFactorQrCodeHeight()
        ));
        
        // OAuth2 info (without secrets)
        summary.put("oauth2", Map.of(
            "google_enabled", customConfigService.isOauth2GoogleEnabled(),
            "github_enabled", customConfigService.isOauth2GitHubEnabled(),
            "success_url", customConfigService.getOauth2SuccessUrl(),
            "failure_url", customConfigService.getOauth2FailureUrl()
        ));
        
        // Rate limiting
        summary.put("rate_limiting", Map.of(
            "enabled", customConfigService.isRateLimitingEnabled(),
            "login_max_attempts", customConfigService.getRateLimitingLoginMaxAttempts(),
            "api_max_requests", customConfigService.getRateLimitingApiMaxRequests()
        ));
        
        // Environment
        summary.put("environment", Map.of(
            "name", customConfigService.getEnvironmentName(),
            "debug", customConfigService.isEnvironmentDebug(),
            "frontend_url", customConfigService.getEnvironmentFrontendUrl(),
            "api_url", customConfigService.getEnvironmentApiUrl()
        ));
        
        // Features
        summary.put("features", Map.of(
            "registration_enabled", customConfigService.isRegistrationEnabled(),
            "email_verification_required", customConfigService.isRegistrationRequireEmailVerification(),
            "auto_login_after_registration", customConfigService.isRegistrationAutoLoginAfterRegistration()
        ));
        
        return ResponseEntity.ok(summary);
    }

    /**
     * Validate current configuration
     */
    @GetMapping("/validate")
    public ResponseEntity<MessageResponse> validateConfiguration() {
        boolean isValid = customConfigService.validateConfiguration();
        
        if (isValid) {
            return ResponseEntity.ok(new MessageResponse("✅ Configuration is valid"));
        } else {
            return ResponseEntity.badRequest()
                    .body(new MessageResponse("⚠️ Configuration has warnings or errors. Check application logs."));
        }
    }

    /**
     * Get configuration help/guide
     */
    @GetMapping("/guide")
    public ResponseEntity<Map<String, Object>> getConfigurationGuide() {
        Map<String, Object> guide = new HashMap<>();
        
        guide.put("title", "Custom Configuration Guide");
        guide.put("description", "How to customize your Authentication Server using app.config.yaml");
        
        Map<String, String> steps = new HashMap<>();
        steps.put("step1", "Create a file named 'app.config.yaml' in your application directory");
        steps.put("step2", "Copy the configuration sections you want to customize from the template");
        steps.put("step3", "Modify the values according to your requirements");
        steps.put("step4", "Restart the application to apply changes");
        guide.put("steps", steps);
        
        Map<String, String> examples = new HashMap<>();
        examples.put("database", "app:\\n  database:\\n    type: postgresql\\n    host: localhost\\n    username: myuser\\n    password: mypassword");
        examples.put("jwt", "jwt:\\n  secret: your-super-secret-jwt-key-here\\n  expiration: 86400000");
        examples.put("email", "email:\\n  smtp:\\n    host: smtp.gmail.com\\n    port: 587\\n    username: your-email@gmail.com\\n    password: your-app-password");
        examples.put("oauth2", "oauth2:\\n  google:\\n    enabled: true\\n    client-id: your-google-client-id\\n    client-secret: your-google-client-secret");
        guide.put("examples", examples);
        
        Map<String, String> warnings = new HashMap<>();
        warnings.put("security", "Never commit sensitive information like passwords or secrets to version control");
        warnings.put("jwt_secret", "Use a strong, randomly generated JWT secret (minimum 32 characters)");
        warnings.put("admin_password", "Change the default admin password immediately after first setup");
        warnings.put("production", "Use strong credentials and proper security settings in production");
        guide.put("warnings", warnings);
        
        return ResponseEntity.ok(guide);
    }

    /**
     * Get environment-specific recommendations
     */
    @GetMapping("/recommendations")
    public ResponseEntity<Map<String, Object>> getEnvironmentRecommendations() {
        Map<String, Object> recommendations = new HashMap<>();
        
        String environment = customConfigService.getEnvironmentName();
        recommendations.put("current_environment", environment);
        
        Map<String, Object> envRecommendations = new HashMap<>();
        
        if (customConfigService.isDevelopmentEnvironment()) {
            envRecommendations.put("database", "H2 in-memory database is suitable for development");
            envRecommendations.put("email", "Use console email output or local SMTP server");
            envRecommendations.put("security", "Relaxed security settings are acceptable");
            envRecommendations.put("debug", "Debug mode can be enabled");
        } else if (customConfigService.isTestingEnvironment()) {
            envRecommendations.put("database", "Use H2 or dedicated test database");
            envRecommendations.put("email", "Mock email services recommended");
            envRecommendations.put("security", "Use test-specific JWT secrets");
            envRecommendations.put("oauth2", "Use test OAuth2 applications");
        } else if (customConfigService.isProductionEnvironment()) {
            envRecommendations.put("database", "Use PostgreSQL or MySQL with proper credentials");
            envRecommendations.put("email", "Configure production SMTP server");
            envRecommendations.put("security", "Use strong JWT secrets and enable all security features");
            envRecommendations.put("ssl", "Enable HTTPS/SSL");
            envRecommendations.put("monitoring", "Enable application monitoring and logging");
            envRecommendations.put("backups", "Configure database backups");
        }
        
        recommendations.put("recommendations", envRecommendations);
        
        return ResponseEntity.ok(recommendations);
    }

    /**
     * Get current active configuration file status
     */
    @GetMapping("/file-status")
    public ResponseEntity<Map<String, Object>> getConfigFileStatus() {
        Map<String, Object> status = new HashMap<>();
        
        java.io.File configFile = new java.io.File("app.config.yaml");
        status.put("file_exists", configFile.exists());
        status.put("file_path", configFile.getAbsolutePath());
        status.put("file_readable", configFile.canRead());
        
        if (configFile.exists()) {
            status.put("file_size", configFile.length());
            status.put("last_modified", configFile.lastModified());
        }
        
        status.put("using_custom_config", configFile.exists() && configFile.canRead());
        status.put("message", configFile.exists() 
            ? "✅ Using custom configuration file" 
            : "ℹ️ Using default configuration (app.config.yaml not found)");
        
        return ResponseEntity.ok(status);
    }
}

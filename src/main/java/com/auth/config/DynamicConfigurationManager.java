package com.auth.config;

import com.auth.service.ConfigurationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.MutablePropertySources;

import java.util.HashMap;
import java.util.Map;

@Configuration
public class DynamicConfigurationManager {
    
    @Autowired
    private ConfigurationService configurationService;
    
    @Autowired
    private ConfigurableEnvironment environment;
    
    private static final String DYNAMIC_PROPERTY_SOURCE_NAME = "dynamicConfiguration";
    
    @EventListener
    public void handleContextRefresh(ContextRefreshedEvent event) {
        updateEnvironmentProperties();
    }
    
    public void updateEnvironmentProperties() {
        Map<String, Object> dynamicProperties = new HashMap<>();
        
        // Load all configurations from database and map to Spring properties
        try {
            // JWT Configuration
            String jwtSecret = configurationService.getConfigValue("jwt.secret");
            if (jwtSecret != null) {
                dynamicProperties.put("app.jwtSecret", jwtSecret);
            }
            
            String jwtExpiration = configurationService.getConfigValue("jwt.expiration.ms");
            if (jwtExpiration != null) {
                dynamicProperties.put("app.jwtExpirationMs", jwtExpiration);
            }
            
            String jwtRefreshExpiration = configurationService.getConfigValue("jwt.refresh.expiration.ms");
            if (jwtRefreshExpiration != null) {
                dynamicProperties.put("app.jwtRefreshExpirationMs", jwtRefreshExpiration);
            }
            
            // Email Configuration
            String emailHost = configurationService.getConfigValue("email.smtp.host");
            if (emailHost != null) {
                dynamicProperties.put("spring.mail.host", emailHost);
            }
            
            String emailPort = configurationService.getConfigValue("email.smtp.port");
            if (emailPort != null) {
                dynamicProperties.put("spring.mail.port", emailPort);
            }
            
            String emailUsername = configurationService.getConfigValue("email.smtp.username");
            if (emailUsername != null) {
                dynamicProperties.put("spring.mail.username", emailUsername);
            }
            
            String emailPassword = configurationService.getConfigValue("email.smtp.password");
            if (emailPassword != null) {
                dynamicProperties.put("spring.mail.password", emailPassword);
            }
            
            // OAuth2 Configuration
            String googleClientId = configurationService.getConfigValue("oauth2.google.client.id");
            if (googleClientId != null) {
                dynamicProperties.put("spring.security.oauth2.client.registration.google.client-id", googleClientId);
            }
            
            String googleClientSecret = configurationService.getConfigValue("oauth2.google.client.secret");
            if (googleClientSecret != null) {
                dynamicProperties.put("spring.security.oauth2.client.registration.google.client-secret", googleClientSecret);
            }
            
            // Security Configuration
            String passwordMinLength = configurationService.getConfigValue("security.password.min.length");
            if (passwordMinLength != null) {
                dynamicProperties.put("app.security.password.min.length", passwordMinLength);
            }
            
            String maxLoginAttempts = configurationService.getConfigValue("security.max.login.attempts");
            if (maxLoginAttempts != null) {
                dynamicProperties.put("app.security.max.login.attempts", maxLoginAttempts);
            }
            
            // 2FA Configuration
            String tfaIssuer = configurationService.getConfigValue("2fa.issuer.name");
            if (tfaIssuer != null) {
                dynamicProperties.put("app.2fa.issuer.name", tfaIssuer);
            }
            
            // Logging Configuration
            String loggingLevel = configurationService.getConfigValue("logging.level");
            if (loggingLevel != null) {
                dynamicProperties.put("logging.level.com.auth", loggingLevel);
            }
            
            // Update the environment with dynamic properties
            MutablePropertySources propertySources = environment.getPropertySources();
            
            // Remove existing dynamic property source if present
            if (propertySources.contains(DYNAMIC_PROPERTY_SOURCE_NAME)) {
                propertySources.remove(DYNAMIC_PROPERTY_SOURCE_NAME);
            }
            
            // Add new dynamic property source with highest priority
            propertySources.addFirst(new MapPropertySource(DYNAMIC_PROPERTY_SOURCE_NAME, dynamicProperties));
            
        } catch (Exception e) {
            // If configuration service is not available yet, skip
            System.err.println("Failed to load dynamic configurations: " + e.getMessage());
        }
    }
    
    public void refreshConfiguration() {
        updateEnvironmentProperties();
    }
}

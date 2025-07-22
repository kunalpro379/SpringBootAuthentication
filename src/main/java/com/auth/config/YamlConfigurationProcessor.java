package com.auth.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.MutablePropertySources;
import org.springframework.stereotype.Component;
import org.yaml.snakeyaml.Yaml;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;

/**
 * YAML Configuration Processor that reads app.config.yaml
 * and applies custom configurations to override defaults
 */
@Component
public class YamlConfigurationProcessor implements ApplicationListener<ApplicationReadyEvent> {

    @Autowired
    private ConfigurableEnvironment environment;

    @Autowired
    private CustomConfigurationLoader customConfigLoader;

    private static final String CONFIG_FILE_NAME = "app.config.yaml";
    private static final String PROPERTY_SOURCE_NAME = "customYamlConfig";

    @Override
    public void onApplicationEvent(ApplicationReadyEvent event) {
        loadCustomYamlConfiguration();
    }

    private void loadCustomYamlConfiguration() {
        try {
            // Try to load app.config.yaml from the application directory
            java.io.File configFile = new java.io.File(CONFIG_FILE_NAME);
            
            if (configFile.exists() && configFile.canRead()) {
                System.out.println("📁 Found custom configuration file: " + configFile.getAbsolutePath());
                
                try (InputStream inputStream = new FileInputStream(configFile)) {
                    Yaml yaml = new Yaml();
                    Map<String, Object> yamlData = yaml.load(inputStream);
                    
                    if (yamlData != null && !yamlData.isEmpty()) {
                        // Flatten the YAML structure for Spring properties
                        Map<String, Object> flattenedProperties = flattenYamlMap("", yamlData);
                        
                        // Add custom property source with high priority
                        MutablePropertySources propertySources = environment.getPropertySources();
                        propertySources.addFirst(new MapPropertySource(PROPERTY_SOURCE_NAME, flattenedProperties));
                        
                        System.out.println("✅ Successfully loaded " + flattenedProperties.size() + " custom configuration properties");
                        
                        // Log some key configurations that were loaded
                        logKeyConfigurations(flattenedProperties);
                        
                    } else {
                        System.out.println("⚠️ Configuration file is empty or invalid");
                    }
                }
            } else {
                System.out.println("ℹ️ No custom configuration file found (" + CONFIG_FILE_NAME + "). Using default settings.");
                System.out.println("💡 Tip: Create an 'app.config.yaml' file in the application directory to customize settings.");
            }
        } catch (IOException e) {
            System.err.println("❌ Error reading custom configuration file: " + e.getMessage());
            System.out.println("⚠️ Falling back to default configuration");
        } catch (Exception e) {
            System.err.println("❌ Unexpected error processing custom configuration: " + e.getMessage());
            System.out.println("⚠️ Falling back to default configuration");
        }
    }

    /**
     * Flattens nested YAML structure into dot-notation properties
     * Example: server.port, app.database.type, etc.
     */
    private Map<String, Object> flattenYamlMap(String prefix, Map<String, Object> map) {
        Map<String, Object> flattened = new HashMap<>();
        
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            String key = prefix.isEmpty() ? entry.getKey() : prefix + "." + entry.getKey();
            Object value = entry.getValue();
            
            if (value instanceof Map) {
                // Recursively flatten nested maps
                @SuppressWarnings("unchecked")
                Map<String, Object> nestedMap = (Map<String, Object>) value;
                flattened.putAll(flattenYamlMap(key, nestedMap));
            } else {
                // Add leaf values
                flattened.put(key, value);
            }
        }
        
        return flattened;
    }

    /**
     * Logs important configuration values that were loaded
     */
    private void logKeyConfigurations(Map<String, Object> properties) {
        System.out.println("\n🔧 Key Configuration Overrides:");
        System.out.println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        
        // Server configuration
        if (properties.containsKey("server.port")) {
            System.out.println("🖥️  Server Port: " + properties.get("server.port"));
        }
        
        // Database configuration
        if (properties.containsKey("app.database.type")) {
            System.out.println("🗄️  Database Type: " + properties.get("app.database.type"));
        }
        if (properties.containsKey("app.database.host")) {
            System.out.println("🔗 Database Host: " + properties.get("app.database.host"));
        }
        
        // JWT configuration
        if (properties.containsKey("jwt.expiration")) {
            long expiration = Long.parseLong(properties.get("jwt.expiration").toString());
            System.out.println("🔐 JWT Expiration: " + (expiration / 3600000) + " hours");
        }
        
        // Email configuration
        if (properties.containsKey("email.smtp.host")) {
            System.out.println("📧 SMTP Host: " + properties.get("email.smtp.host"));
        }
        
        // Two-factor authentication
        if (properties.containsKey("two-factor.enabled")) {
            System.out.println("🔒 2FA Enabled: " + properties.get("two-factor.enabled"));
        }
        
        // OAuth2 configuration
        if (properties.containsKey("oauth2.google.enabled")) {
            System.out.println("🔑 Google OAuth2: " + properties.get("oauth2.google.enabled"));
        }
        if (properties.containsKey("oauth2.github.enabled")) {
            System.out.println("🔑 GitHub OAuth2: " + properties.get("oauth2.github.enabled"));
        }
        
        // Environment
        if (properties.containsKey("environment.name")) {
            System.out.println("🌍 Environment: " + properties.get("environment.name"));
        }
        if (properties.containsKey("environment.frontend-url")) {
            System.out.println("🌐 Frontend URL: " + properties.get("environment.frontend-url"));
        }
        
        System.out.println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    }

    /**
     * Validates that required configurations are present
     */
    private boolean validateConfiguration(Map<String, Object> properties) {
        boolean isValid = true;
        
        // Check for critical configurations
        if (properties.containsKey("jwt.secret")) {
            String jwtSecret = properties.get("jwt.secret").toString();
            if (jwtSecret.length() < 32) {
                System.err.println("⚠️ WARNING: JWT secret is too short (minimum 32 characters recommended)");
                isValid = false;
            }
        }
        
        if (properties.containsKey("admin.default-user.password")) {
            String adminPassword = properties.get("admin.default-user.password").toString();
            if ("admin123".equals(adminPassword)) {
                System.err.println("⚠️ WARNING: Default admin password detected! Change it immediately for security.");
            }
        }
        
        return isValid;
    }

    /**
     * Provides configuration validation and suggestions
     */
    public void printConfigurationGuide() {
        System.out.println("\n📋 Configuration Guide:");
        System.out.println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        System.out.println("To customize your authentication server, create an 'app.config.yaml' file");
        System.out.println("in the application directory with your desired settings.");
        System.out.println("");
        System.out.println("Example app.config.yaml structure:");
        System.out.println("  server:");
        System.out.println("    port: 4554");
        System.out.println("  app:");
        System.out.println("    database:");
        System.out.println("      type: postgresql");
        System.out.println("      host: localhost");
        System.out.println("      username: myuser");
        System.out.println("      password: mypassword");
        System.out.println("  jwt:");
        System.out.println("    secret: your-super-secret-jwt-key");
        System.out.println("    expiration: 86400000");
        System.out.println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    }
}

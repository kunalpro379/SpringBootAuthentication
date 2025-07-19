package com.auth.service;

import com.auth.dto.ConfigurationRequest;
import com.auth.dto.ConfigurationResponse;
import com.auth.dto.MessageResponse;
import com.auth.entity.ConfigCategory;
import com.auth.entity.ConfigType;
import com.auth.entity.SystemConfiguration;
import com.auth.repository.SystemConfigurationRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
@Transactional
public class ConfigurationServiceImpl implements ConfigurationService {
    
    @Autowired
    private SystemConfigurationRepository configRepository;
    
    @Override
    public List<ConfigurationResponse> getAllConfigurations() {
        return configRepository.findAll().stream()
                .map(this::convertToResponse)
                .collect(Collectors.toList());
    }
    
    @Override
    public List<ConfigurationResponse> getConfigurationsByCategory(ConfigCategory category) {
        return configRepository.findByCategoryOrderByConfigKey(category).stream()
                .map(this::convertToResponse)
                .collect(Collectors.toList());
    }
    
    @Override
    public ConfigurationResponse getConfigurationByKey(String key) {
        Optional<SystemConfiguration> config = configRepository.findByConfigKey(key);
        return config.map(this::convertToResponse).orElse(null);
    }
    
    @Override
    public MessageResponse createConfiguration(ConfigurationRequest request, String createdBy) {
        if (configRepository.existsByConfigKey(request.getConfigKey())) {
            return new MessageResponse("Configuration with key '" + request.getConfigKey() + "' already exists");
        }
        
        SystemConfiguration config = new SystemConfiguration();
        config.setConfigKey(request.getConfigKey());
        config.setConfigValue(request.getConfigValue());
        config.setDescription(request.getDescription());
        config.setCategory(request.getCategory());
        config.setType(request.getType());
        config.setSecure(request.isSecure());
        config.setEditable(request.isEditable());
        config.setCreatedBy(createdBy);
        config.setUpdatedBy(createdBy);
        
        configRepository.save(config);
        return new MessageResponse("Configuration created successfully");
    }
    
    @Override
    public MessageResponse updateConfiguration(String key, ConfigurationRequest request, String updatedBy) {
        Optional<SystemConfiguration> configOpt = configRepository.findByConfigKey(key);
        
        if (configOpt.isEmpty()) {
            return new MessageResponse("Configuration with key '" + key + "' not found");
        }
        
        SystemConfiguration config = configOpt.get();
        
        if (!config.isEditable()) {
            return new MessageResponse("Configuration '" + key + "' is not editable");
        }
        
        config.setConfigValue(request.getConfigValue());
        config.setDescription(request.getDescription());
        config.setCategory(request.getCategory());
        config.setType(request.getType());
        config.setSecure(request.isSecure());
        config.setUpdatedBy(updatedBy);
        
        configRepository.save(config);
        return new MessageResponse("Configuration updated successfully");
    }
    
    @Override
    public MessageResponse deleteConfiguration(String key) {
        Optional<SystemConfiguration> configOpt = configRepository.findByConfigKey(key);
        
        if (configOpt.isEmpty()) {
            return new MessageResponse("Configuration with key '" + key + "' not found");
        }
        
        SystemConfiguration config = configOpt.get();
        
        if (!config.isEditable()) {
            return new MessageResponse("Configuration '" + key + "' cannot be deleted");
        }
        
        configRepository.delete(config);
        return new MessageResponse("Configuration deleted successfully");
    }
    
    @Override
    public String getConfigValue(String key) {
        return configRepository.findByConfigKey(key)
                .map(SystemConfiguration::getConfigValue)
                .orElse(null);
    }
    
    @Override
    public String getConfigValue(String key, String defaultValue) {
        return configRepository.findByConfigKey(key)
                .map(SystemConfiguration::getConfigValue)
                .orElse(defaultValue);
    }
    
    @Override
    public void initializeDefaultConfigurations() {
        createDefaultConfigIfNotExists("jwt.secret", "mySecretKey", 
                "JWT Secret Key", ConfigCategory.JWT, ConfigType.PASSWORD, true, false);
        
        createDefaultConfigIfNotExists("jwt.expiration.ms", "86400000", 
                "JWT Token Expiration in milliseconds", ConfigCategory.JWT, ConfigType.INTEGER, false, true);
        
        createDefaultConfigIfNotExists("jwt.refresh.expiration.ms", "604800000", 
                "JWT Refresh Token Expiration in milliseconds", ConfigCategory.JWT, ConfigType.INTEGER, false, true);
        
        createDefaultConfigIfNotExists("email.smtp.host", "smtp.gmail.com", 
                "SMTP Server Host", ConfigCategory.EMAIL, ConfigType.STRING, false, true);
        
        createDefaultConfigIfNotExists("email.smtp.port", "587", 
                "SMTP Server Port", ConfigCategory.EMAIL, ConfigType.INTEGER, false, true);
        
        createDefaultConfigIfNotExists("email.smtp.username", "", 
                "SMTP Username", ConfigCategory.EMAIL, ConfigType.EMAIL, false, true);
        
        createDefaultConfigIfNotExists("email.smtp.password", "", 
                "SMTP Password", ConfigCategory.EMAIL, ConfigType.PASSWORD, true, true);
        
        createDefaultConfigIfNotExists("oauth2.google.client.id", "", 
                "Google OAuth2 Client ID", ConfigCategory.OAUTH2, ConfigType.STRING, false, true);
        
        createDefaultConfigIfNotExists("oauth2.google.client.secret", "", 
                "Google OAuth2 Client Secret", ConfigCategory.OAUTH2, ConfigType.PASSWORD, true, true);
        
        createDefaultConfigIfNotExists("security.password.min.length", "8", 
                "Minimum Password Length", ConfigCategory.SECURITY, ConfigType.INTEGER, false, true);
        
        createDefaultConfigIfNotExists("security.session.timeout", "30", 
                "Session Timeout in minutes", ConfigCategory.SECURITY, ConfigType.INTEGER, false, true);
        
        createDefaultConfigIfNotExists("security.max.login.attempts", "5", 
                "Maximum Login Attempts", ConfigCategory.SECURITY, ConfigType.INTEGER, false, true);
        
        createDefaultConfigIfNotExists("2fa.issuer.name", "AuthServer", 
                "2FA Issuer Name", ConfigCategory.TWO_FACTOR, ConfigType.STRING, false, true);
        
        createDefaultConfigIfNotExists("app.name", "Authentication Server", 
                "Application Name", ConfigCategory.GENERAL, ConfigType.STRING, false, true);
        
        createDefaultConfigIfNotExists("app.version", "1.0.0", 
                "Application Version", ConfigCategory.GENERAL, ConfigType.STRING, false, false);
        
        createDefaultConfigIfNotExists("logging.level", "INFO", 
                "Application Logging Level", ConfigCategory.LOGGING, ConfigType.STRING, false, true);
    }
    
    private void createDefaultConfigIfNotExists(String key, String value, String description, 
                                              ConfigCategory category, ConfigType type, 
                                              boolean isSecure, boolean isEditable) {
        if (!configRepository.existsByConfigKey(key)) {
            SystemConfiguration config = new SystemConfiguration(key, value, description, category, type);
            config.setSecure(isSecure);
            config.setEditable(isEditable);
            config.setCreatedBy("SYSTEM");
            config.setUpdatedBy("SYSTEM");
            configRepository.save(config);
        }
    }
    
    @Override
    public MessageResponse resetToDefaults() {
        configRepository.deleteAll();
        initializeDefaultConfigurations();
        return new MessageResponse("All configurations reset to defaults");
    }
    
    @Override
    public List<ConfigurationResponse> getEditableConfigurations() {
        return configRepository.findByIsEditableTrue().stream()
                .map(this::convertToResponse)
                .collect(Collectors.toList());
    }
    
    private ConfigurationResponse convertToResponse(SystemConfiguration config) {
        ConfigurationResponse response = new ConfigurationResponse();
        response.setId(config.getId());
        response.setConfigKey(config.getConfigKey());
        response.setConfigValue(config.getConfigValue());
        response.setDescription(config.getDescription());
        response.setCategory(config.getCategory());
        response.setType(config.getType());
        response.setSecure(config.isSecure());
        response.setEditable(config.isEditable());
        response.setCreatedBy(config.getCreatedBy());
        response.setUpdatedBy(config.getUpdatedBy());
        response.setCreatedAt(config.getCreatedAt());
        response.setUpdatedAt(config.getUpdatedAt());
        return response;
    }
}

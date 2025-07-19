package com.auth.service;

import com.auth.dto.ConfigurationRequest;
import com.auth.dto.ConfigurationResponse;
import com.auth.dto.MessageResponse;
import com.auth.entity.ConfigCategory;
import com.auth.entity.SystemConfiguration;

import java.util.List;

public interface ConfigurationService {
    
    List<ConfigurationResponse> getAllConfigurations();
    
    List<ConfigurationResponse> getConfigurationsByCategory(ConfigCategory category);
    
    ConfigurationResponse getConfigurationByKey(String key);
    
    MessageResponse createConfiguration(ConfigurationRequest request, String createdBy);
    
    MessageResponse updateConfiguration(String key, ConfigurationRequest request, String updatedBy);
    
    MessageResponse deleteConfiguration(String key);
    
    String getConfigValue(String key);
    
    String getConfigValue(String key, String defaultValue);
    
    void initializeDefaultConfigurations();
    
    MessageResponse resetToDefaults();
    
    List<ConfigurationResponse> getEditableConfigurations();
}

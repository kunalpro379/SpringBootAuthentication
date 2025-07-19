package com.auth.dto;

import com.auth.entity.ConfigCategory;
import com.auth.entity.ConfigType;
import jakarta.validation.constraints.NotBlank;

public class ConfigurationRequest {
    
    @NotBlank
    private String configKey;
    
    private String configValue;
    private String description;
    private ConfigCategory category;
    private ConfigType type;
    private boolean isSecure = false;
    private boolean isEditable = true;
    
    // Constructors
    public ConfigurationRequest() {}
    
    public ConfigurationRequest(String configKey, String configValue, String description, 
                              ConfigCategory category, ConfigType type) {
        this.configKey = configKey;
        this.configValue = configValue;
        this.description = description;
        this.category = category;
        this.type = type;
    }
    
    // Getters and Setters
    public String getConfigKey() { return configKey; }
    public void setConfigKey(String configKey) { this.configKey = configKey; }
    
    public String getConfigValue() { return configValue; }
    public void setConfigValue(String configValue) { this.configValue = configValue; }
    
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    
    public ConfigCategory getCategory() { return category; }
    public void setCategory(ConfigCategory category) { this.category = category; }
    
    public ConfigType getType() { return type; }
    public void setType(ConfigType type) { this.type = type; }
    
    public boolean isSecure() { return isSecure; }
    public void setSecure(boolean secure) { isSecure = secure; }
    
    public boolean isEditable() { return isEditable; }
    public void setEditable(boolean editable) { isEditable = editable; }
}

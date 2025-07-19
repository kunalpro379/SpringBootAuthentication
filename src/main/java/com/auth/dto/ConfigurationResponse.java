package com.auth.dto;

import com.auth.entity.ConfigCategory;
import com.auth.entity.ConfigType;

import java.time.LocalDateTime;

public class ConfigurationResponse {
    
    private Long id;
    private String configKey;
    private String configValue;
    private String description;
    private ConfigCategory category;
    private ConfigType type;
    private boolean isSecure;
    private boolean isEditable;
    private String createdBy;
    private String updatedBy;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    
    // Constructor
    public ConfigurationResponse() {}
    
    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    
    public String getConfigKey() { return configKey; }
    public void setConfigKey(String configKey) { this.configKey = configKey; }
    
    public String getConfigValue() { 
        // Don't return actual value for secure configs
        return isSecure ? "********" : configValue; 
    }
    public void setConfigValue(String configValue) { this.configValue = configValue; }
    
    public String getActualConfigValue() { return configValue; }
    
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
    
    public String getCreatedBy() { return createdBy; }
    public void setCreatedBy(String createdBy) { this.createdBy = createdBy; }
    
    public String getUpdatedBy() { return updatedBy; }
    public void setUpdatedBy(String updatedBy) { this.updatedBy = updatedBy; }
    
    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }
    
    public LocalDateTime getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(LocalDateTime updatedAt) { this.updatedAt = updatedAt; }
}

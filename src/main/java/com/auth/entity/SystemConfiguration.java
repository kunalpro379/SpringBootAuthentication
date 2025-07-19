package com.auth.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import java.time.LocalDateTime;

@Entity
@Table(name = "system_configurations")
public class SystemConfiguration {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @NotBlank
    @Column(unique = true)
    private String configKey;
    
    @Column(columnDefinition = "TEXT")
    private String configValue;
    
    @Size(max = 500)
    private String description;
    
    @Enumerated(EnumType.STRING)
    private ConfigCategory category;
    
    @Enumerated(EnumType.STRING)
    private ConfigType type;
    
    private boolean isSecure = false;  // For sensitive configs like passwords
    private boolean isEditable = true;  // Some configs might be read-only
    
    @Column(name = "created_by")
    private String createdBy;
    
    @Column(name = "updated_by")
    private String updatedBy;
    
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    
    public SystemConfiguration() {}
    
    public SystemConfiguration(String configKey, String configValue, String description, 
                             ConfigCategory category, ConfigType type) {
        this.configKey = configKey;
        this.configValue = configValue;
        this.description = description;
        this.category = category;
        this.type = type;
        this.createdAt = LocalDateTime.now();
        this.updatedAt = LocalDateTime.now();
    }
    
    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        updatedAt = LocalDateTime.now();
    }
    
    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }
    
    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    
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
    
    public String getCreatedBy() { return createdBy; }
    public void setCreatedBy(String createdBy) { this.createdBy = createdBy; }
    
    public String getUpdatedBy() { return updatedBy; }
    public void setUpdatedBy(String updatedBy) { this.updatedBy = updatedBy; }
    
    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }
    
    public LocalDateTime getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(LocalDateTime updatedAt) { this.updatedAt = updatedAt; }
}

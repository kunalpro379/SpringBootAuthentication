package com.auth.controller;

import com.auth.dto.ConfigurationRequest;
import com.auth.dto.ConfigurationResponse;
import com.auth.dto.MessageResponse;
import com.auth.entity.ConfigCategory;
import com.auth.service.ConfigurationService;
import com.auth.service.UserDetailsImpl;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/admin/config")
@PreAuthorize("hasRole('ADMIN')")
public class ConfigurationController {
    
    @Autowired
    private ConfigurationService configurationService;
    
    @GetMapping("/all")
    public ResponseEntity<List<ConfigurationResponse>> getAllConfigurations() {
        return ResponseEntity.ok(configurationService.getAllConfigurations());
    }
    
    @GetMapping("/category/{category}")
    public ResponseEntity<List<ConfigurationResponse>> getConfigurationsByCategory(
            @PathVariable ConfigCategory category) {
        return ResponseEntity.ok(configurationService.getConfigurationsByCategory(category));
    }
    
    @GetMapping("/editable")
    public ResponseEntity<List<ConfigurationResponse>> getEditableConfigurations() {
        return ResponseEntity.ok(configurationService.getEditableConfigurations());
    }
    
    @GetMapping("/{key}")
    public ResponseEntity<ConfigurationResponse> getConfiguration(@PathVariable String key) {
        ConfigurationResponse config = configurationService.getConfigurationByKey(key);
        if (config != null) {
            return ResponseEntity.ok(config);
        }
        return ResponseEntity.notFound().build();
    }
    
    @PostMapping
    public ResponseEntity<MessageResponse> createConfiguration(
            @Valid @RequestBody ConfigurationRequest request) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        UserDetailsImpl userDetails = (UserDetailsImpl) auth.getPrincipal();
        
        MessageResponse response = configurationService.createConfiguration(request, userDetails.getUsername());
        return ResponseEntity.ok(response);
    }
    
    @PutMapping("/{key}")
    public ResponseEntity<MessageResponse> updateConfiguration(
            @PathVariable String key,
            @Valid @RequestBody ConfigurationRequest request) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        UserDetailsImpl userDetails = (UserDetailsImpl) auth.getPrincipal();
        
        MessageResponse response = configurationService.updateConfiguration(key, request, userDetails.getUsername());
        return ResponseEntity.ok(response);
    }
    
    @DeleteMapping("/{key}")
    public ResponseEntity<MessageResponse> deleteConfiguration(@PathVariable String key) {
        MessageResponse response = configurationService.deleteConfiguration(key);
        return ResponseEntity.ok(response);
    }
    
    @PostMapping("/reset-defaults")
    public ResponseEntity<MessageResponse> resetToDefaults() {
        MessageResponse response = configurationService.resetToDefaults();
        return ResponseEntity.ok(response);
    }
    
    @PostMapping("/initialize")
    public ResponseEntity<MessageResponse> initializeDefaults() {
        configurationService.initializeDefaultConfigurations();
        return ResponseEntity.ok(new MessageResponse("Default configurations initialized"));
    }
}

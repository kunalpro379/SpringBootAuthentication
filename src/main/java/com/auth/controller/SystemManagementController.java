package com.auth.controller;

import com.auth.config.DynamicConfigurationManager;
import com.auth.dto.MessageResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/admin/system")
@PreAuthorize("hasRole('ADMIN')")
public class SystemManagementController {
    
    @Autowired
    private DynamicConfigurationManager configManager;
    
    @PostMapping("/reload-config")
    public ResponseEntity<MessageResponse> reloadConfiguration() {
        try {
            configManager.refreshConfiguration();
            return ResponseEntity.ok(new MessageResponse("Configuration reloaded successfully"));
        } catch (Exception e) {
            return ResponseEntity.internalServerError()
                    .body(new MessageResponse("Failed to reload configuration: " + e.getMessage()));
        }
    }
    
    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> systemHealth() {
        Map<String, Object> health = Map.of(
                "status", "UP",
                "timestamp", System.currentTimeMillis(),
                "jvm", Map.of(
                        "memory", Map.of(
                                "max", Runtime.getRuntime().maxMemory(),
                                "total", Runtime.getRuntime().totalMemory(),
                                "free", Runtime.getRuntime().freeMemory()
                        )
                )
        );
        return ResponseEntity.ok(health);
    }
    
    @PostMapping("/gc")
    public ResponseEntity<MessageResponse> forceGarbageCollection() {
        System.gc();
        return ResponseEntity.ok(new MessageResponse("Garbage collection triggered"));
    }
}

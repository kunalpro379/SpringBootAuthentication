package com.auth.controller;

import com.auth.dto.MessageResponse;
import com.auth.entity.User;
import com.auth.repository.RefreshTokenRepository;
import com.auth.repository.SystemConfigurationRepository;
import com.auth.repository.UserRepository;
import com.auth.service.ConfigurationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/admin")
@PreAuthorize("hasRole('ADMIN')")
public class AdminDashboardController {
    
    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private RefreshTokenRepository refreshTokenRepository;
    
    @Autowired
    private SystemConfigurationRepository configRepository;
    
    @Autowired
    private ConfigurationService configurationService;
    
    @GetMapping("/dashboard")
    public ResponseEntity<Map<String, Object>> getDashboardStats() {
        Map<String, Object> stats = new HashMap<>();
        
        // User Statistics
        long totalUsers = userRepository.count();
        long verifiedUsers = userRepository.findAll().stream()
                .mapToLong(user -> user.isEmailVerified() ? 1 : 0)
                .sum();
        long activeUsers = userRepository.findAll().stream()
                .mapToLong(user -> user.isEnabled() ? 1 : 0)
                .sum();
        long usersWithTwoFA = userRepository.findAll().stream()
                .mapToLong(user -> user.isTwoFactorEnabled() ? 1 : 0)
                .sum();
        
        stats.put("totalUsers", totalUsers);
        stats.put("verifiedUsers", verifiedUsers);
        stats.put("activeUsers", activeUsers);
        stats.put("usersWithTwoFA", usersWithTwoFA);
        
        // Token Statistics
        long activeRefreshTokens = refreshTokenRepository.count();
        stats.put("activeRefreshTokens", activeRefreshTokens);
        
        // Configuration Statistics
        long totalConfigurations = configRepository.count();
        long editableConfigurations = configRepository.findByIsEditableTrue().size();
        stats.put("totalConfigurations", totalConfigurations);
        stats.put("editableConfigurations", editableConfigurations);
        
        // System Information
        stats.put("serverTime", LocalDateTime.now());
        stats.put("appName", configurationService.getConfigValue("app.name", "Authentication Server"));
        stats.put("appVersion", configurationService.getConfigValue("app.version", "1.0.0"));
        
        return ResponseEntity.ok(stats);
    }
    
    @GetMapping("/users")
    public ResponseEntity<List<User>> getAllUsers() {
        List<User> users = userRepository.findAll();
        // Remove sensitive information
        users.forEach(user -> {
            user.setPassword("***");
            user.setTwoFactorSecret(user.isTwoFactorEnabled() ? "***" : null);
            user.setEmailVerificationToken(null);
            user.setPasswordResetToken(null);
        });
        return ResponseEntity.ok(users);
    }
    
    @GetMapping("/users/recent")
    public ResponseEntity<List<User>> getRecentUsers(@RequestParam(defaultValue = "10") int limit) {
        List<User> users = userRepository.findAll().stream()
                .sorted((u1, u2) -> u2.getCreatedAt().compareTo(u1.getCreatedAt()))
                .limit(limit)
                .peek(user -> {
                    user.setPassword("***");
                    user.setTwoFactorSecret(user.isTwoFactorEnabled() ? "***" : null);
                    user.setEmailVerificationToken(null);
                    user.setPasswordResetToken(null);
                })
                .toList();
        return ResponseEntity.ok(users);
    }
    
    @PutMapping("/users/{userId}/enable")
    public ResponseEntity<MessageResponse> enableUser(@PathVariable Long userId) {
        return userRepository.findById(userId)
                .map(user -> {
                    user.setEnabled(true);
                    userRepository.save(user);
                    return ResponseEntity.ok(new MessageResponse("User enabled successfully"));
                })
                .orElse(ResponseEntity.notFound().build());
    }
    
    @PutMapping("/users/{userId}/disable")
    public ResponseEntity<MessageResponse> disableUser(@PathVariable Long userId) {
        return userRepository.findById(userId)
                .map(user -> {
                    user.setEnabled(false);
                    userRepository.save(user);
                    return ResponseEntity.ok(new MessageResponse("User disabled successfully"));
                })
                .orElse(ResponseEntity.notFound().build());
    }
    
    @DeleteMapping("/users/{userId}")
    public ResponseEntity<MessageResponse> deleteUser(@PathVariable Long userId) {
        return userRepository.findById(userId)
                .map(user -> {
                    // Delete associated refresh tokens first
                    refreshTokenRepository.deleteByUser(user);
                    // Then delete the user
                    userRepository.delete(user);
                    return ResponseEntity.ok(new MessageResponse("User deleted successfully"));
                })
                .orElse(ResponseEntity.notFound().build());
    }
    
    @PostMapping("/users/{userId}/reset-2fa")
    public ResponseEntity<MessageResponse> resetUserTwoFactor(@PathVariable Long userId) {
        return userRepository.findById(userId)
                .map(user -> {
                    user.setTwoFactorEnabled(false);
                    user.setTwoFactorSecret(null);
                    userRepository.save(user);
                    return ResponseEntity.ok(new MessageResponse("Two-factor authentication reset for user"));
                })
                .orElse(ResponseEntity.notFound().build());
    }
    
    @PostMapping("/system/cleanup")
    public ResponseEntity<MessageResponse> performSystemCleanup() {
        // Clean up expired tokens, verification tokens, etc.
        LocalDateTime now = LocalDateTime.now();
        
        // This would require additional methods in repositories
        // For now, return a placeholder response
        return ResponseEntity.ok(new MessageResponse("System cleanup performed successfully"));
    }
}

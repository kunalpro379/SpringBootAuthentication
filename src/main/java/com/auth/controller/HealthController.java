package com.auth.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import java.util.Map;

@RestController
public class HealthController {
     @GetMapping("/health")
     public Map<String, Object> health() {
          return Map.of(
                    "status", "UP",
                    "message", "Authentication server is running");
     }
}
package com.auth.dto;

import java.util.List;

public class JwtResponseDto {
     private String token;
     private String type = "Bearer";
     private String refreshToken;
     private Long id;
     private String username;
     private String email;
     private List<String> roles;
     private boolean requiresTwoFactor;

     public JwtResponseDto(String accessToken,
               String refreshToken,
               Long id,
               String username,
               String email,
               List<String> roles) {
          this.token = accessToken;
          this.refreshToken = refreshToken;
          this.id = id;
          this.username = username;
          this.email = email;
          this.roles = roles;
     }

     public JwtResponseDto(
               String accessToken,
               String refreshToken,
               Long id,
               String username,
               String email,
               List<String> roles,
               boolean requiresTwoFactor

     ) {
          this.token = accessToken;
          this.refreshToken = refreshToken;
          this.id = id;
          this.username = username;
          this.email = email;
          this.roles = roles;
          this.requiresTwoFactor = requiresTwoFactor;
     }

     // Getters and Setters
     public String getAccessToken() {
          return token;
     }

     public void setAccessToken(String accessToken) {
          this.token = accessToken;
     }

     public String getTokenType() {
          return type;
     }

     public void setTokenType(String tokenType) {
          this.type = tokenType;
     }

     public String getRefreshToken() {
          return refreshToken;
     }

     public void setRefreshToken(String refreshToken) {
          this.refreshToken = refreshToken;
     }

     public Long getId() {
          return id;
     }

     public void setId(Long id) {
          this.id = id;
     }

     public String getEmail() {
          return email;
     }

     public void setEmail(String email) {
          this.email = email;
     }

     public String getUsername() {
          return username;
     }

     public void setUsername(String username) {
          this.username = username;
     }

     public List<String> getRoles() {
          return roles;
     }

     public boolean isRequiresTwoFactor() {
          return requiresTwoFactor;
     }

     public void setRequiresTwoFactor(boolean requiresTwoFactor) {
          this.requiresTwoFactor = requiresTwoFactor;
     }
}

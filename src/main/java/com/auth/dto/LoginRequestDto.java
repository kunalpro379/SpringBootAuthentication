package com.auth.dto;

import jakarta.validation.constraints.NotBlank;

public class LoginRequestDto {
     @NotBlank
     private String usernameOrEmail;

     @NotBlank
     private String password;
     private String twoFactorCode;

     public String getUsernameOrEmail() {
          return usernameOrEmail;
     }

     public void setUsernameOrEmail(String usernameOrEmail) {
          this.usernameOrEmail = usernameOrEmail;
     }

     public String getPassword() {
          return password;
     }

     public void setPassword(String password) {
          this.password = password;
     }

     public String getTwoFactorCode() {
          return twoFactorCode;
     }

     public void setTwoFactorCode(String twoFactorCode) {
          this.twoFactorCode = twoFactorCode;
     }

}

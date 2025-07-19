package com.auth.dto;

import jakarta.validation.constraints.NotBlank;
public class TwoFactorAuthRequestDto {
     @NotBlank
    private String code;
     public String getCode() {return code; }
    public void setCode(String code) { this.code = code; }
}

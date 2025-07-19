package com.auth.dto;

public class TwoFactorSetupResponseDto {
     private String qrCodeUrl;
     private String secretKey;
     private String[] backupCodes;

     public TwoFactorSetupResponseDto(
          String qrCodeUrl,
          String secret,
          String[] backupCodes){
               this.qrCodeUrl=qrCodeUrl;
               this.secretKey=secret;
               this.backupCodes=backupCodes;
     }

     public String getQrCodeUrl() {
          return qrCodeUrl;
     }

     public void setQrCodeUrl(String qrCodeUrl) {
          this.qrCodeUrl = qrCodeUrl;
     }

     public String getSecret() {
          return secretKey;
     }

     public void setSecret(String secret) {
          this.secretKey = secret;
     }

     public String[] getBackupCodes() {
          return backupCodes;
     }

     public void setBackupCodes(String[] backupCodes) {
          this.backupCodes = backupCodes;
     }
}

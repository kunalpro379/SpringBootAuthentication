package com.auth.dto;

public class TwoFactorSetupResponseDto {
     private String qrCodeUrl;
     private String secretKey;
     private String[] backupCodes;

     public TwoFactorSetupResponse(
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
          return secret;
     }

     public void setSecret(String secret) {
          this.secret = secret;
     }

     public String[] getBackupCodes() {
          return backupCodes;
     }

     public void setBackupCodes(String[] backupCodes) {
          this.backupCodes = backupCodes;
     }
}

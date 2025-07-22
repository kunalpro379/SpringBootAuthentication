package com.auth.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class EmailService {
    
    @Autowired
    private JavaMailSender mailSender;
    
    public void sendVerificationEmail(String to, String token) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(to);
        message.setSubject("Email Verification");
        message.setText("Please click the following link to verify your email: " +
                "http://localhost:4554/api/auth/verify-email?token=" + token);
        
        mailSender.send(message);
    }
    
    public void sendPasswordResetEmail(String to, String token) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(to);
        message.setSubject("Password Reset");
        message.setText("Please click the following link to reset your password: " +
                "http://localhost:3000/reset-password?token=" + token);
        
        mailSender.send(message);
    }
    
    public void sendTwoFactorSetupEmail(String to) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(to);
        message.setSubject("Two-Factor Authentication Enabled");
        message.setText("Two-factor authentication has been successfully enabled for your account.");
        
        mailSender.send(message);
    }
}

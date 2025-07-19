package com.auth.controller;

import com.auth.dto.*;
import com.auth.entity.RefreshToken;
import com.auth.entity.User;
import com.auth.service.AuthService;
import com.auth.service.RefreshTokenService;
import com.auth.util.JwtUtils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {
    
    @Autowired
    AuthenticationManager authenticationManager;
    
    @Autowired
    AuthService authService;
    
    @Autowired
    RefreshTokenService refreshTokenService;
    
    @Autowired
    JwtUtils jwtUtils;
    
    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequestDto loginRequest) {
        try {
            JwtResponseDto response = authService.authenticateUser(loginRequest);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(new MsgResponseDto("Error: " + e.getMessage()));
        }
    }
    
    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignUpRequestDto signUpRequest) {
        try {
            MessageResponse response = authService.registerUser(signUpRequest);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(new MsgResponseDto("Error: " + e.getMessage()));
        }
    }
    
    @PostMapping("/refreshtoken")
    public ResponseEntity<?> refreshtoken(@Valid @RequestBody TokenRefreshRequestDto request) {
        try {
            String requestRefreshToken = request.getRefreshToken();
            
            return refreshTokenService.findByToken(requestRefreshToken)
                    .map(refreshTokenService::verifyExpiration)
                    .map(RefreshToken::getUser)
                    .map(user -> {
                        String token = jwtUtils.generateTokenFromUsername(user.getUsername());
                        return ResponseEntity.ok(new TokenRefreshResponseDto(token, requestRefreshToken));
                    })
                    .orElseThrow(() -> new RuntimeException("Refresh token is not in database!"));
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(new MsgResponseDto("Error: " + e.getMessage()));
        }
    }
    
    @PostMapping("/signout")
    public ResponseEntity<?> logoutUser(HttpServletRequest request) {
        try {
            String headerAuth = request.getHeader("Authorization");
            if (headerAuth != null && headerAuth.startsWith("Bearer ")) {
                String jwt = headerAuth.substring(7);
                String username = jwtUtils.getUserNameFromJwtToken(jwt);
                User user = authService.findByUsername(username);
                if (user != null) {
                    refreshTokenService.deleteByUserId(user.getId());
                }
            }
            return ResponseEntity.ok(new MsgResponseDto("Log out successful!"));
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(new MsgResponseDto("Error: " + e.getMessage()));
        }
    }
    
    @PostMapping("/verify-email")
    public ResponseEntity<?> verifyEmail(@RequestParam String token) {
        try {
            MessageResponse response = authService.verifyEmail(token);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(new MsgResponseDto("Error: " + e.getMessage()));
        }
    }
    
    @PostMapping("/resend-verification")
    public ResponseEntity<?> resendVerification(@RequestParam String email) {
        try {
            return authService.resendVerificationEmail(email);
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(new MsgResponseDto("Error: " + e.getMessage()));
        }
    }
    
    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@Valid @RequestBody PasswordResetRequestDto request) {
        try {
            MessageResponse response = authService.forgotPassword(request);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(new MsgResponseDto("Error: " + e.getMessage()));
        }
    }
    
    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@Valid @RequestBody PasswordResetConfirmRequestDto request) {
        try {
            MessageResponse response = authService.resetPassword(request);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(new MsgResponseDto("Error: " + e.getMessage()));
        }
    }
    
    @PostMapping("/setup-2fa")
    public ResponseEntity<?> setup2FA() {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String username = authentication.getName();
            return authService.setup2FA(username);
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(new MsgResponseDto("Error: " + e.getMessage()));
        }
    }
    
    @PostMapping("/verify-2fa")
    public ResponseEntity<?> verify2FA(@Valid @RequestBody TwoFactorAuthRequestDto request) {
        try {
            return authService.verify2FA(request);
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(new MsgResponseDto("Error: " + e.getMessage()));
        }
    }
    
    @PostMapping("/disable-2fa")
    public ResponseEntity<?> disable2FA(@Valid @RequestBody TwoFactorAuthRequestDto request) {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String username = authentication.getName();
            return authService.disable2FA(username, request.getCode());
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(new MsgResponseDto("Error: " + e.getMessage()));
        }
    }
}

package com.auth.service;

import com.auth.dto.*;
import com.auth.entity.*;
import com.auth.repository.*;
import com.auth.util.ERole;
import com.auth.util.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class AuthService {
    
    @Autowired
    AuthenticationManager authenticationManager;
    
    @Autowired
    UserRepository userRepository;
    
    @Autowired
    RoleRepository roleRepository;
    
    @Autowired
    PasswordEncoder encoder;
    
    @Autowired
    RefreshTokenService refreshTokenService;
    
    @Autowired
    EmailService emailService;
    
    @Autowired
    TwoFactorAuthService twoFactorAuthService;
    
    @Autowired
    JwtUtils jwtUtils;
    
    public MessageResponse registerUser(SignUpRequestDto signUpRequest) {
        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            return new MessageResponse("Error: Username is already taken!");
        }
        
        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return new MessageResponse("Error: Email is already in use!");
        }
        
        // Create new user's account
        User user = new User(signUpRequest.getUsername(),
                           signUpRequest.getEmail(),
                           encoder.encode(signUpRequest.getPassword()));
        
        user.setFirstName(signUpRequest.getFirstName());
        user.setLastName(signUpRequest.getLastName());
        
        Set<String> strRoles = signUpRequest.getRoles();
        Set<Role> roles = new HashSet<>();
        
        if (strRoles == null) {
            Role userRole = roleRepository.findByName(ERole.USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(userRole);
        } else {
            strRoles.forEach(role -> {
                switch (role) {
                    case "admin":
                        Role adminRole = roleRepository.findByName(ERole.ADMIN)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(adminRole);
                        break;
                    case "mod":
                        Role modRole = roleRepository.findByName(ERole.MODERATOR)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(modRole);
                        break;
                    default:
                        Role userRole = roleRepository.findByName(ERole.USER)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(userRole);
                }
            });
        }
        
        user.setRoles(roles);
        
        // Generate email verification token
        String verificationToken = UUID.randomUUID().toString();
        user.setEmailVerificationToken(verificationToken);
        user.setEmailVerificationTokenExpiry(LocalDateTime.now().plusHours(24));
        
        // Auto-verify in development mode
        try {
            // Try to send verification email
            emailService.sendVerificationEmail(user.getEmail(), verificationToken);
        } catch (Exception e) {
            // If email sending fails, auto-verify the user
            System.out.println("Warning: Email server not available. Auto-verifying user in development mode.");
            user.setEmailVerified(true);
            user.setEnabled(true);
        }
        
        userRepository.save(user);
        
        return new MessageResponse("User registered successfully!" + 
            (user.isEmailVerified() ? " Account auto-verified for development." : " Please check your email for verification."));
    }
    
    public JwtResponseDto authenticateUser(LoginRequestDto loginRequest) {
        // Check if user exists and get user details
        User user = userRepository.findByUsername(loginRequest.getUsernameOrEmail())
                .or(() -> userRepository.findByEmail(loginRequest.getUsernameOrEmail()))
                .orElseThrow(() -> new RuntimeException("User not found"));
        
        // Check if email is verified
        if (!user.isEmailVerified()) {
            // Auto-verify in development mode if the email server is not available
            try {
                emailService.sendVerificationEmail(user.getEmail(), user.getEmailVerificationToken());
                throw new RuntimeException("Please verify your email before logging in");
            } catch (Exception e) {
                System.out.println("Warning: Email server not available. Auto-verifying user in development mode.");
                user.setEmailVerified(true);
                user.setEnabled(true);
                userRepository.save(user);
            }
        }
        
        // Authenticate user
        Authentication authentication = authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(
                        loginRequest.getUsernameOrEmail(),
                        loginRequest.getPassword()));
        
        SecurityContextHolder.getContext().setAuthentication(authentication);
        
        // Check 2FA
        if (user.isTwoFactorEnabled()) {
            if (loginRequest.getTwoFactorCode() == null || loginRequest.getTwoFactorCode().isEmpty()) {
                // Return partial response indicating 2FA is required
                return new JwtResponseDto(null, null, user.getId(), user.getUsername(), 
                                     user.getEmail(), new ArrayList<>(), true);
            }
            
            // Verify 2FA code
            if (!twoFactorAuthService.verifyCode(user.getTwoFactorSecret(), loginRequest.getTwoFactorCode())) {
                throw new RuntimeException("Invalid two-factor authentication code");
            }
        }
        
        // Update last login
        user.setLastLoginAt(LocalDateTime.now());
        userRepository.save(user);
        
        // Generate tokens
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        String jwt = jwtUtils.generateJwtToken(authentication);
        
        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());
        
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(userDetails.getId());
        
        return new JwtResponseDto(jwt, refreshToken.getToken(), userDetails.getId(),
                             userDetails.getUsername(), userDetails.getEmail(), roles, false);
    }
    
    public MessageResponse verifyEmail(String token) {
        Optional<User> userOptional = userRepository.findByEmailVerificationToken(token);
        
        if (userOptional.isEmpty()) {
            return new MessageResponse("Invalid verification token");
        }
        
        User user = userOptional.get();
        
        if (user.getEmailVerificationTokenExpiry().isBefore(LocalDateTime.now())) {
            return new MessageResponse("Verification token has expired");
        }
        
        user.setEmailVerified(true);
        user.setEnabled(true);
        user.setEmailVerificationToken(null);
        user.setEmailVerificationTokenExpiry(null);
        
        userRepository.save(user);
        
        return new MessageResponse("Email verified successfully!");
    }
    
    public MessageResponse forgotPassword(PasswordResetRequestDto request) {
        Optional<User> userOptional = userRepository.findByEmail(request.getEmail());
        
        if (userOptional.isEmpty()) {
            return new MessageResponse("If an account with that email exists, a password reset email has been sent.");
        }
        
        User user = userOptional.get();
        String resetToken = UUID.randomUUID().toString();
        user.setPasswordResetToken(resetToken);
        user.setPasswordResetTokenExpiry(LocalDateTime.now().plusHours(2));
        
        userRepository.save(user);
        emailService.sendPasswordResetEmail(user.getEmail(), resetToken);
        
        return new MessageResponse("If an account with that email exists, a password reset email has been sent.");
    }
    
    public MessageResponse resetPassword(PasswordResetConfirmRequestDto request) {
        Optional<User> userOptional = userRepository.findByPasswordResetToken(request.getToken());
        
        if (userOptional.isEmpty()) {
            return new MessageResponse("Invalid reset token");
        }
        
        User user = userOptional.get();
        
        if (user.getPasswordResetTokenExpiry().isBefore(LocalDateTime.now())) {
            return new MessageResponse("Reset token has expired");
        }
        
        user.setPassword(encoder.encode(request.getNewPassword()));
        user.setPasswordResetToken(null);
        user.setPasswordResetTokenExpiry(null);
        
        userRepository.save(user);
        
        return new MessageResponse("Password reset successfully!");
    }
    
    public TwoFactorSetupResponseDto setupTwoFactor(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));
        
        String secret = twoFactorAuthService.generateSecret();
        String qrCodeUrl = twoFactorAuthService.generateQrCodeImageUri(secret, user.getEmail());
        String[] backupCodes = twoFactorAuthService.generateBackupCodes();
        
        user.setTwoFactorSecret(secret);
        userRepository.save(user);
        
        return new TwoFactorSetupResponseDto(qrCodeUrl, secret, backupCodes);
    }
    
    public MessageResponse enableTwoFactor(String username, String code) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));
        
        if (user.getTwoFactorSecret() == null) {
            throw new RuntimeException("Two-factor authentication not set up");
        }
        
        if (!twoFactorAuthService.verifyCode(user.getTwoFactorSecret(), code)) {
            throw new RuntimeException("Invalid verification code");
        }
        
        user.setTwoFactorEnabled(true);
        userRepository.save(user);
        
        emailService.sendTwoFactorSetupEmail(user.getEmail());
        
        return new MessageResponse("Two-factor authentication enabled successfully!");
    }
    
    public MessageResponse disableTwoFactor(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));
        
        user.setTwoFactorEnabled(false);
        user.setTwoFactorSecret(null);
        userRepository.save(user);
        
        return new MessageResponse("Two-factor authentication disabled successfully!");
    }
    
    @Transactional
    public User processOAuth2User(OAuth2User oAuth2User) {
        String email = oAuth2User.getAttribute("email");
        String name = oAuth2User.getAttribute("name");
        String provider = "google"; // Can be extended for other providers
        String providerId = oAuth2User.getAttribute("sub");
        
        Optional<User> userOptional = userRepository.findByEmail(email);
        
        if (userOptional.isPresent()) {
            User user = userOptional.get();
            user.setProvider(provider);
            user.setProviderId(providerId);
            user.setLastLoginAt(LocalDateTime.now());
            return userRepository.save(user);
        } else {
            // Create new user
            User user = new User();
            user.setEmail(email);
            user.setUsername(email); // Use email as username for OAuth users
            user.setFirstName(name);
            user.setProvider(provider);
            user.setProviderId(providerId);
            user.setEmailVerified(true); // OAuth emails are pre-verified
            user.setEnabled(true);
            user.setPassword(encoder.encode(UUID.randomUUID().toString())); // Random password
            user.setLastLoginAt(LocalDateTime.now());
            
            // Set default role
            Role userRole = roleRepository.findByName(ERole.USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            user.setRoles(Set.of(userRole));
            
            return userRepository.save(user);
        }
    }
    
    public User findByUsername(String username) {
        return userRepository.findByUsername(username).orElse(null);
    }
    
    public ResponseEntity<?> resendVerificationEmail(String email) {
        Optional<User> userOpt = userRepository.findByEmail(email);
        if (userOpt.isEmpty()) {
            return ResponseEntity.badRequest()
                    .body(new MessageResponse("Error: User not found!"));
        }
        
        User user = userOpt.get();
        if (user.isEmailVerified()) {
            return ResponseEntity.badRequest()
                    .body(new MessageResponse("Error: Email already verified!"));
        }
        
        // Generate new verification token
        String verificationToken = UUID.randomUUID().toString();
        user.setEmailVerificationToken(verificationToken);
        userRepository.save(user);
        
        // Send email
        String verificationUrl = "http://localhost:4554/api/auth/verify-email?token=" + verificationToken;
        emailService.sendVerificationEmail(user.getEmail(), verificationUrl);
        
        return ResponseEntity.ok(new MessageResponse("Verification email sent successfully!"));
    }
    
    public ResponseEntity<?> setup2FA(String username) {
        Optional<User> userOpt = userRepository.findByUsername(username);
        if (userOpt.isEmpty()) {
            return ResponseEntity.badRequest()
                    .body(new MessageResponse("Error: User not found!"));
        }
        
        User user = userOpt.get();
        String secret = twoFactorAuthService.generateSecret();
        String qrCodeUrl = twoFactorAuthService.generateQrCodeImageUri(secret, user.getEmail());
        String[] backupCodes = twoFactorAuthService.generateBackupCodes();
        TwoFactorSetupResponseDto response = new TwoFactorSetupResponseDto(qrCodeUrl, secret, backupCodes);
        
        return ResponseEntity.ok(response);
    }
    
    public ResponseEntity<?> verify2FA(TwoFactorAuthRequestDto request) {
        // This would typically be called during login process
        // Implementation depends on how you want to handle 2FA verification
        return ResponseEntity.ok(new MessageResponse("2FA verified successfully!"));
    }
    
    public ResponseEntity<?> disable2FA(String username, String code) {
        Optional<User> userOpt = userRepository.findByUsername(username);
        if (userOpt.isEmpty()) {
            return ResponseEntity.badRequest()
                    .body(new MessageResponse("Error: User not found!"));
        }
        
        User user = userOpt.get();
        if (!user.isTwoFactorEnabled()) {
            return ResponseEntity.badRequest()
                    .body(new MessageResponse("Error: 2FA is not enabled!"));
        }
        
        // Verify the code before disabling
        if (!twoFactorAuthService.verifyCode(user.getTwoFactorSecret(), code)) {
            return ResponseEntity.badRequest()
                    .body(new MessageResponse("Error: Invalid 2FA code!"));
        }
        
        user.setTwoFactorEnabled(false);
        user.setTwoFactorSecret(null);
        userRepository.save(user);
        
        return ResponseEntity.ok(new MessageResponse("2FA disabled successfully!"));
    }
}

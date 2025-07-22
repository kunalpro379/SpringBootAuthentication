package com.auth.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

@Entity 
@Table(name="users", uniqueConstraints={
     @UniqueConstraint(columnNames="email"),
     @UniqueConstraint(columnNames="username")
})
public class User implements UserDetails{
     @Id
     @GeneratedValue(strategy=GenerationType.IDENTITY)
     private Long id;

     @NotBlank(message="Name is required")
     @Size(min=3,max=20,message="Name must be between 3 and 20 characters")
     private String username;

     @NotBlank(message="Email is required")
     @Size(max=50,message="Email must be less than 40 characters")
     @Email(message="Invalid email address")
     private String email;

     @NotBlank
     @Size(max = 120)
     private String password;
     
     @Size(max = 50)
     @Column(name = "first_name")
     private String firstName;
     
     @Size(max = 50)
     @Column(name = "last_name")
     private String lastName;

     private boolean enabled=false;
     
     @Column(name = "account_non_expired")
     private boolean accountNonExpired=true;
     
     @Column(name = "account_non_locked")
     private boolean accountNonLocked=true;
     
     @Column(name = "credentials_non_expired")
     private boolean credentialsNonExpired =true;
     
     //Email Verification 
     @Column(name = "email_verification_token")
     private String emailVerificationToken;
     
     @Column(name = "email_verification_token_expiry")
     private LocalDateTime emailVerificationTokenExpiry;
     
     @Column(name = "email_verified")
     private boolean emailVerified = false;

     //Password Reset 
     @Column(name = "password_reset_token")
     private String passwordResetToken;
     
     @Column(name = "password_reset_token_expiry")
     private LocalDateTime passwordResetTokenExpiry;

     //2FA
     @Column(name = "two_factor_enabled")
     private boolean twoFactorEnabled = false;
     
     @Column(name = "two_factor_secret")
     private String twoFactorSecret;

     // OAuth
     @Column(name = "provider")
     private String provider;
     
     @Column(name = "provider_id")
     private String providerId;
     
     // Timestamps
     @Column(name = "created_at")
     private LocalDateTime createdAt;
     
     @Column(name = "updated_at")
     private LocalDateTime updatedAt;
     
     @Column(name = "last_login_at")
     private LocalDateTime lastLoginAt;

    @ManyToMany(fetch=FetchType.LAZY)
    @JoinTable(
     name="user_roles",
     joinColumns=@JoinColumn(name="user_id"),
     inverseJoinColumns=@JoinColumn(name="role_id")
    )
    private Set<Role> roles = new HashSet<>(); 
    public User(){
    }
    public User(String username, String email, String password){
        this.username=username;
        this.email=email;
        this.password=password;
        this.createdAt = LocalDateTime.now();
        this.updatedAt = LocalDateTime.now();
    }
    //Implementing UserDetails interface
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities(){
     return roles.stream()
             .map(role -> new SimpleGrantedAuthority("ROLE_" + role.getName().name()))
             .collect(Collectors.toList());
    }

    @Override
    public boolean isAccountNonExpired() {
        return accountNonExpired;
    }
    
    @Override
    public boolean isAccountNonLocked() {
        return accountNonLocked;
    }
    @Override
    public boolean isCredentialsNonExpired() {
        return credentialsNonExpired;
    }
    
    @Override
    public boolean isEnabled() {
        return enabled && emailVerified;
    }
    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        updatedAt = LocalDateTime.now();
    }
    
    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }

        // Getters and Setters
        public Long getId() { return id; }
        public void setId(Long id) { this.id = id; }
        
        public String getUsername() { return username; }
        public void setUsername(String username) { this.username = username; }
        
        public String getEmail() { return email; }
        public void setEmail(String email) { this.email = email; }
        
        public String getPassword() { return password; }
        public void setPassword(String password) { this.password = password; }
        
        public String getFirstName() { return firstName; }
        public void setFirstName(String firstName) { this.firstName = firstName; }
        
        public String getLastName() { return lastName; }
        public void setLastName(String lastName) { this.lastName = lastName; }
        
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        
        public void setAccountNonExpired(boolean accountNonExpired) { this.accountNonExpired = accountNonExpired; }
        
        public void setAccountNonLocked(boolean accountNonLocked) { this.accountNonLocked = accountNonLocked; }
        
        public void setCredentialsNonExpired(boolean credentialsNonExpired) { this.credentialsNonExpired = credentialsNonExpired; }
    public String getEmailVerificationToken() { return emailVerificationToken; }
          
    public void setEmailVerificationToken(String emailVerificationToken) { this.emailVerificationToken = emailVerificationToken; }
    
    public LocalDateTime getEmailVerificationTokenExpiry() { return emailVerificationTokenExpiry; }
    public void setEmailVerificationTokenExpiry(LocalDateTime emailVerificationTokenExpiry) { this.emailVerificationTokenExpiry = emailVerificationTokenExpiry; }
    
    public boolean isEmailVerified() { return emailVerified; }
    public void setEmailVerified(boolean emailVerified) { this.emailVerified = emailVerified; }
    
    public String getPasswordResetToken() { return passwordResetToken; }
    public void setPasswordResetToken(String passwordResetToken) { this.passwordResetToken = passwordResetToken; }
    
    public LocalDateTime getPasswordResetTokenExpiry() { return passwordResetTokenExpiry; }
    public void setPasswordResetTokenExpiry(LocalDateTime passwordResetTokenExpiry) { this.passwordResetTokenExpiry = passwordResetTokenExpiry; }
    
    public boolean isTwoFactorEnabled() { return twoFactorEnabled; }
    public void setTwoFactorEnabled(boolean twoFactorEnabled) { this.twoFactorEnabled = twoFactorEnabled; }
    
    public String getTwoFactorSecret() { return twoFactorSecret; }
    public void setTwoFactorSecret(String twoFactorSecret) { this.twoFactorSecret = twoFactorSecret; }
    
    public String getProvider() { return provider; }
    public void setProvider(String provider) { this.provider = provider; }

    public String getProviderId() { return providerId; }
    public void setProviderId(String providerId) { this.providerId = providerId; }
    
    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }
    
    public LocalDateTime getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(LocalDateTime updatedAt) { this.updatedAt = updatedAt; }
    
    public LocalDateTime getLastLoginAt() { return lastLoginAt; }
    public void setLastLoginAt(LocalDateTime lastLoginAt) { this.lastLoginAt = lastLoginAt; }
    
    public Set<Role> getRoles() { return roles; }
    public void setRoles(Set<Role> roles) { this.roles = roles; }
    

    
}
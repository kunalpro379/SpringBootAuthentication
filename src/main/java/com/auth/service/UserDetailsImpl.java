package com.auth.service;

import com.auth.entity.User;
import com.fasterxml.jackson.annotation.JsonIgnore;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

public class UserDetailsImpl implements UserDetails{
     private static final long serialVersionUID = 1L;
     private Long id;
     private String username;
     private String email;

     @JsonIgnore
     private String password;
     private Collection<? extends GrantedAuthority> authorities;
     private boolean enabled;
     private boolean accountNonExpired;
     private boolean accountNonLocked;
     private boolean credentialsNonExpired;
     private boolean twoFactorEnabled;
     private boolean requiresTwoFactor;
     
     public UserDetailsImpl(
                Long id, String username, String email, String password,
                Collection<? extends GrantedAuthority>authorities,
                boolean enabled, boolean accountNonExpired,
                boolean credentialsNonExpired, boolean accountNonLocked
        ){
            this.id = id;
            this.username = username;
            this.email = email;
            this.password = password;
            this.authorities = authorities;
            this.enabled = enabled;
            this.accountNonExpired = accountNonExpired;
            this.accountNonLocked = accountNonLocked;
            this.credentialsNonExpired = credentialsNonExpired;
        }
        public static UserDetailsImpl build(User user){
             List<GrantedAuthority>authorities=user.getRoles().stream().map(
                     role->
                          new SimpleGrantedAuthority(
                                  "ROLE_"+role.getName().name()
                          )
             ).collect(Collectors.toList());
             return new UserDetailsImpl(
                     user.getId(),
                     user.getUsername(),
                     user.getEmail(),
                     user.getPassword(),
                     authorities,
                     user.isEnabled(),
                     user.isAccountNonExpired(),
                     user.isCredentialsNonExpired(),
                     user.isAccountNonLocked()
             );
        }
        @Override
          public Collection<? extends GrantedAuthority>getAuthorities(){
             return authorities;
        }
     public Long getId() {
          return id;
     }

     public String getEmail() {
          return email;
     }

     @Override
     public String getPassword() {
          return password;
     }

     @Override
     public String getUsername() {
          return username;
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
          return enabled;
     }
     
     public boolean isTwoFactorEnabled() {
          return twoFactorEnabled;
     }
     
     public void setTwoFactorEnabled(boolean twoFactorEnabled) {
          this.twoFactorEnabled = twoFactorEnabled;
     }
     
     public boolean isRequiresTwoFactor() {
          return requiresTwoFactor;
     }
     
     public void setRequiresTwoFactor(boolean requiresTwoFactor) {
          this.requiresTwoFactor = requiresTwoFactor;
     }
     
     @Override
     public boolean equals(Object o){
             if(this==o)return true;
             if(o==null||getClass()!=o.getClass())return false;
             UserDetailsImpl user = (UserDetailsImpl)o;
             return Objects.equals(id, user.id);
     }

}

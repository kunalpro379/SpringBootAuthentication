package com.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import java.util.Set;

public class SignUpRequestDto {
     @NotBlank
     @Size(min = 3, max = 30)
     private String username;

     @NotBlank
     @Size(max = 50)
     @Email
     private String email;

     private Set<String> roles;

     @NotBlank
     @Size(min = 6, max = 120)
     private String password;

     private String firstName;
     private String lastName;

     public String getUsername() {
          return username;
     }

     public void setUsername(String username) {
          this.username = username;
     }

     public String getEmail() {
          return email;
     }

     public void setEmail(String email) {
          this.email = email;
     }

     public String getPassword() {
          return password;
     }

     public void setPassword(String password) {
          this.password = password;
     }

     public Set<String> getRoles() {
          return this.roles;
     }

     public void setRoles(Set<String> roles) {
          this.roles = roles;
     }

     public String getFirstName() {
          return firstName;
     }

     public void setFirstName(String firstName) {
          this.firstName = firstName;
     }

     public String getLastName() {
          return lastName;
     }

     public void setLastName(String lastName) {
          this.lastName = lastName;
     }

}
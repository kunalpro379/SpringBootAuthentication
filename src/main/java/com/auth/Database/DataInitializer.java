package com.auth.Database;

import com.auth.util.ERole;
import com.auth.entity.Role;
import com.auth.entity.User;
import com.auth.repository.RoleRepository;
import com.auth.repository.UserRepository;
import com.auth.service.ConfigurationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.Set;

@Component
public class DataInitializer implements CommandLineRunner {

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private ConfigurationService configurationService;

    @Override
    @Transactional
    public void run(String... args) throws Exception {
        // Initialize roles
        if (roleRepository.count() == 0) {
            roleRepository.save(new Role(ERole.USER));
            roleRepository.save(new Role(ERole.ADMIN));
            roleRepository.save(new Role(ERole.MODERATOR));
        }

        // Initialize system configurations
        configurationService.initializeDefaultConfigurations();

        // Create default admin user if no admin exists
        createDefaultAdminUser();
    }

    private void createDefaultAdminUser() {
        // Check if any admin user exists
        boolean adminExists = userRepository.findAll().stream()
                .peek(user -> user.getRoles().size()) // Force roles to load
                .anyMatch(user -> user.getRoles().stream()
                        .anyMatch(role -> role.getName() == ERole.ADMIN));

        if (!adminExists) {
            User adminUser = new User();
            adminUser.setUsername("admin");
            adminUser.setEmail("admin@authserver.com");
            adminUser.setPassword(passwordEncoder.encode("admin123")); // Default password
            adminUser.setFirstName("System");
            adminUser.setLastName("Administrator");
            adminUser.setEmailVerified(true);
            adminUser.setEnabled(true);

            // Assign ADMIN role
            Role adminRole = roleRepository.findByName(ERole.ADMIN)
                    .orElseThrow(() -> new RuntimeException("Admin role not found"));
            adminUser.setRoles(Set.of(adminRole));

            userRepository.save(adminUser);

            System.out.println("=================================================");
            System.out.println("DEFAULT ADMIN USER CREATED:");
            System.out.println("Username: admin");
            System.out.println("Password: admin123");
            System.out.println("Email: admin@authserver.com");
            System.out.println("PLEASE CHANGE THE DEFAULT PASSWORD IMMEDIATELY!");
            System.out.println("=================================================");
        }
    }
}

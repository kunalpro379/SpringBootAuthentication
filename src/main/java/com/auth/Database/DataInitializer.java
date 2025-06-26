package com.auth.Database;
import com.auth.entity.ERole;
import com.auth.entity.Role;
import com.auth.repository.RoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

@Component
public class DataInitializer implements CommandLineRunner {
     @Autowired
     RoleRepository roleRepository;
     @Override
     public void run(String... args) throws Exception{
          if(roleRepository.count()==0){
               roleRepository.save(new Role(ERole.USER));
               roleRepository.save(new Role(ERole.ADMIN));
               roleRepository.save(new Role(ERole.MODERATOR));
          }
     }
}

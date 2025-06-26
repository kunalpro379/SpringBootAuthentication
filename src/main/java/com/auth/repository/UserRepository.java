package com.auth.repository;

import com.auth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
     Optional<User> findByUsername(String username);

     Optional<User> findByEmail(String email);

     Optional<User> findByEmailVerificationToken(String token);

     Optional<User> findByPasswordResetToken(String token);

     Boolean existsByUsername(String username);

     Boolean existsByEmail(String email);

     void deleteByEmailVerificationTokenExpiryBefore(LocalDateTime datetime);

     void deleteByPasswordResetTokenExpiryBefore(LocalDateTime dateTime);
}
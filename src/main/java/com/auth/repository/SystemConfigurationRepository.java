package com.auth.repository;

import com.auth.entity.ConfigCategory;
import com.auth.entity.SystemConfiguration;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface SystemConfigurationRepository extends JpaRepository<SystemConfiguration, Long> {
    
    Optional<SystemConfiguration> findByConfigKey(String configKey);
    
    List<SystemConfiguration> findByCategory(ConfigCategory category);
    
    List<SystemConfiguration> findByIsEditableTrue();
    
    List<SystemConfiguration> findByCategoryOrderByConfigKey(ConfigCategory category);
    
    boolean existsByConfigKey(String configKey);
}

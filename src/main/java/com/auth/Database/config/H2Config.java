package com.auth.Database.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;

import javax.sql.DataSource;

@Configuration
@ConditionalOnProperty(name = "app.database.type", havingValue = "h2", matchIfMissing = true)
public class H2Config {
    
    @Autowired
    private DatabaseProperties databaseProperties;
    
    @Bean
    @Primary
    @ConfigurationProperties("app.database.pool")
    public HikariConfig hikariConfig() {
        HikariConfig config = new HikariConfig();
        config.setJdbcUrl(databaseProperties.getJdbcUrl());
        config.setUsername(databaseProperties.getUsername());
        config.setPassword(databaseProperties.getPassword());
        config.setDriverClassName(databaseProperties.getDriverClassName());
        
        // Connection pool settings from properties
        config.setMaximumPoolSize(databaseProperties.getPool().getMaximumSize());
        config.setMinimumIdle(databaseProperties.getPool().getMinimumIdle());
        config.setConnectionTimeout(databaseProperties.getPool().getConnectionTimeout());
        config.setIdleTimeout(databaseProperties.getPool().getIdleTimeout());
        config.setMaxLifetime(databaseProperties.getPool().getMaxLifetime());
        
        // H2 specific optimizations
        config.addDataSourceProperty("cachePrepStmts", "true");
        config.addDataSourceProperty("prepStmtCacheSize", "250");
        config.addDataSourceProperty("prepStmtCacheSqlLimit", "2048");
        
        return config;
    }
    
    @Bean
    @Primary
    public DataSource dataSource() {
        return new HikariDataSource(hikariConfig());
    }
}

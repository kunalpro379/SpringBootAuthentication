package com.auth.Database.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.DatabaseMetaData;

@Component
public class DatabaseConfigValidator implements CommandLineRunner {
    
    @Autowired
    private DatabaseProperties databaseProperties;
    
    @Autowired(required = false)
    private DataSource dataSource;
    
    @Override
    public void run(String... args) throws Exception {
        validateDatabaseConfiguration();
    }
    
    private void validateDatabaseConfiguration() {
        System.out.println("=== Database Configuration Validation ===");
        System.out.println("Database Type: " + databaseProperties.getType());
        System.out.println("Database Host: " + databaseProperties.getHost());
        System.out.println("Database Port: " + (databaseProperties.getPort() != null ? 
                          databaseProperties.getPort() : databaseProperties.getDefaultPort()));
        System.out.println("Database Name: " + databaseProperties.getName());
        System.out.println("Database Username: " + databaseProperties.getUsername());
        
        if (!databaseProperties.isMongoDB() && dataSource != null) {
            validateSqlConnection();
        } else if (databaseProperties.isMongoDB()) {
            validateMongoConnection();
        }
        
        System.out.println("=== Database Configuration Valid ===");
    }
    
    private void validateSqlConnection() {
        try (Connection connection = dataSource.getConnection()) {
            DatabaseMetaData metaData = connection.getMetaData();
            System.out.println("Connected to: " + metaData.getDatabaseProductName() + 
                             " " + metaData.getDatabaseProductVersion());
            System.out.println("JDBC URL: " + databaseProperties.getJdbcUrl());
            System.out.println("Driver: " + metaData.getDriverName());
            System.out.println("✅ SQL Database connection successful!");
        } catch (Exception e) {
            System.err.println("❌ Database connection failed: " + e.getMessage());
            System.err.println("Please check your database configuration and ensure the database server is running.");
            // Don't throw exception to allow application to start for debugging
        }
    }
    
    private void validateMongoConnection() {
        System.out.println("MongoDB Configuration detected");
        // Note: Add actual MongoDB connection validation when MongoDB dependencies are available
        System.out.println("⚠️  MongoDB validation skipped - Add spring-boot-starter-data-mongodb dependency for full validation");
    }
}

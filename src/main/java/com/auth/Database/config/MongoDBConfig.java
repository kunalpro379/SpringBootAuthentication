package com.auth.Database.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConditionalOnProperty(name = "app.database.type", havingValue = "mongodb", matchIfMissing = false)
public class MongoDBConfig {
    
    @Autowired
    private DatabaseProperties databaseProperties;
    
    // Note: MongoDB configuration will be activated when MongoDB dependencies are added
    // Add these dependencies to pom.xml:
    // <dependency>
    //     <groupId>org.springframework.boot</groupId>
    //     <artifactId>spring-boot-starter-data-mongodb</artifactId>
    // </dependency>
    
    public String getConnectionString() {
        StringBuilder connectionString = new StringBuilder("mongodb://");
        
        // Add authentication if username is provided
        if (databaseProperties.getUsername() != null && !databaseProperties.getUsername().isEmpty()) {
            connectionString.append(databaseProperties.getUsername());
            if (databaseProperties.getPassword() != null && !databaseProperties.getPassword().isEmpty()) {
                connectionString.append(":").append(databaseProperties.getPassword());
            }
            connectionString.append("@");
        }
        
        // Add host and port
        connectionString.append(databaseProperties.getHost());
        Integer port = databaseProperties.getPort() != null ? 
                      databaseProperties.getPort() : databaseProperties.getDefaultPort();
        connectionString.append(":").append(port);
        
        // Add database name
        connectionString.append("/").append(databaseProperties.getName());
        
        // Add authentication database if specified
        if (databaseProperties.getMongodb().getAuthenticationDatabase() != null) {
            connectionString.append("?authSource=")
                           .append(databaseProperties.getMongodb().getAuthenticationDatabase());
        }
        
        // Add replica set if specified
        if (databaseProperties.getMongodb().getReplicaSet() != null && 
            !databaseProperties.getMongodb().getReplicaSet().isEmpty()) {
            String separator = connectionString.toString().contains("?") ? "&" : "?";
            connectionString.append(separator)
                           .append("replicaSet=")
                           .append(databaseProperties.getMongodb().getReplicaSet());
        }
        
        // Add SSL if enabled
        if (databaseProperties.getMongodb().getSslEnabled()) {
            String separator = connectionString.toString().contains("?") ? "&" : "?";
            connectionString.append(separator).append("ssl=true");
        }
        
        return connectionString.toString();
    }
}

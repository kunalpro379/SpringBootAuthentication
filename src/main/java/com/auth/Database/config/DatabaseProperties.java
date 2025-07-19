package com.auth.Database.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Data
@Component
@ConfigurationProperties(prefix = "app.database")
public class DatabaseProperties {
    
    private String type = "h2"; // postgresql, mysql, mongodb, h2
    private String host = "localhost";
    private Integer port;
    private String name = "authdb";
    private String username;
    private String password;
    
    private Pool pool = new Pool();
    private MongoDB mongodb = new MongoDB();
    private Options options = new Options();
    
    @Data
    public static class Pool {
        private Integer maximumSize = 20;
        private Integer minimumIdle = 5;
        private Long connectionTimeout = 30000L;
        private Long idleTimeout = 600000L;
        private Long maxLifetime = 1800000L;
    }
    
    @Data
    public static class MongoDB {
        private String authenticationDatabase = "admin";
        private String replicaSet;
        private Boolean sslEnabled = false;
    }
    
    @Data
    public static class Options {
        private Boolean createDatabaseIfNotExist = true;
        private Boolean showSql = false;
        private Boolean formatSql = false;
    }
    
    // Helper methods
    public boolean isPostgreSQL() {
        return "postgresql".equalsIgnoreCase(type);
    }
    
    public boolean isMySQL() {
        return "mysql".equalsIgnoreCase(type);
    }
    
    public boolean isMongoDB() {
        return "mongodb".equalsIgnoreCase(type);
    }
    
    public boolean isH2() {
        return "h2".equalsIgnoreCase(type);
    }
    
    public Integer getDefaultPort() {
        switch (type.toLowerCase()) {
            case "postgresql":
                return 5432;
            case "mysql":
                return 3306;
            case "mongodb":
                return 27017;
            case "h2":
                return 9092;
            default:
                return port != null ? port : 5432;
        }
    }
    
    public String getJdbcUrl() {
        if (isMongoDB()) {
            return null; // MongoDB doesn't use JDBC
        }
        
        Integer dbPort = port != null ? port : getDefaultPort();
        
        switch (type.toLowerCase()) {
            case "postgresql":
                return String.format("jdbc:postgresql://%s:%d/%s", host, dbPort, name);
            case "mysql":
                return String.format("jdbc:mysql://%s:%d/%s?useSSL=false&serverTimezone=UTC&allowPublicKeyRetrieval=true", 
                                   host, dbPort, name);
            case "h2":
                if ("localhost".equals(host)) {
                    return String.format("jdbc:h2:mem:%s", name);
                } else {
                    return String.format("jdbc:h2:tcp://%s:%d/%s", host, dbPort, name);
                }
            default:
                throw new IllegalArgumentException("Unsupported database type: " + type);
        }
    }
    
    public String getDriverClassName() {
        switch (type.toLowerCase()) {
            case "postgresql":
                return "org.postgresql.Driver";
            case "mysql":
                return "com.mysql.cj.jdbc.Driver";
            case "h2":
                return "org.h2.Driver";
            default:
                throw new IllegalArgumentException("Unsupported database type: " + type);
        }
    }
    
    public String getDialect() {
        switch (type.toLowerCase()) {
            case "postgresql":
                return "org.hibernate.dialect.PostgreSQLDialect";
            case "mysql":
                return "org.hibernate.dialect.MySQL8Dialect";
            case "h2":
                return "org.hibernate.dialect.H2Dialect";
            default:
                throw new IllegalArgumentException("Unsupported database type: " + type);
        }
    }
}

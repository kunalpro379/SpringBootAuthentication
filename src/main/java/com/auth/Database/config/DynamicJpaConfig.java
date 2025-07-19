package com.auth.Database.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.orm.jpa.JpaVendorAdapter;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.orm.jpa.vendor.HibernateJpaVendorAdapter;
import org.springframework.transaction.annotation.EnableTransactionManagement;

import javax.sql.DataSource;
import java.util.Properties;

@Configuration
@EnableTransactionManagement
@ConditionalOnProperty(name = "app.database.type", havingValue = "h2,postgresql,mysql", matchIfMissing = true)
public class DynamicJpaConfig {
    
    @Autowired
    private DatabaseProperties databaseProperties;
    
    @Autowired
    private DataSource dataSource;
    
    @Bean
    public LocalContainerEntityManagerFactoryBean entityManagerFactory() {
        LocalContainerEntityManagerFactoryBean em = new LocalContainerEntityManagerFactoryBean();
        em.setDataSource(dataSource);
        em.setPackagesToScan("com.auth.entity");
        
        JpaVendorAdapter vendorAdapter = new HibernateJpaVendorAdapter();
        em.setJpaVendorAdapter(vendorAdapter);
        em.setJpaProperties(additionalProperties());
        
        return em;
    }
    
    private Properties additionalProperties() {
        Properties properties = new Properties();
        
        // Set dialect based on database type
        properties.setProperty("hibernate.dialect", databaseProperties.getDialect());
        
        // Set other JPA properties
        properties.setProperty("hibernate.show_sql", 
                              databaseProperties.getOptions().getShowSql().toString());
        properties.setProperty("hibernate.format_sql", 
                              databaseProperties.getOptions().getFormatSql().toString());
        
        // Performance optimizations
        properties.setProperty("hibernate.jdbc.batch_size", "25");
        properties.setProperty("hibernate.order_inserts", "true");
        properties.setProperty("hibernate.order_updates", "true");
        properties.setProperty("hibernate.jdbc.lob.non_contextual_creation", "true");
        
        // Connection handling
        properties.setProperty("hibernate.connection.provider_disables_autocommit", "true");
        
        // Database specific optimizations
        if (databaseProperties.isPostgreSQL()) {
            properties.setProperty("hibernate.temp.use_jdbc_metadata_defaults", "false");
        } else if (databaseProperties.isMySQL()) {
            properties.setProperty("hibernate.connection.useUnicode", "true");
            properties.setProperty("hibernate.connection.characterEncoding", "utf8");
        }
        
        return properties;
    }
}

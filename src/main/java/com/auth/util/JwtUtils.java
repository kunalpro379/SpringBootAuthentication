package com.auth.util;

import com.auth.service.UserDetailsImpl;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import java.security.Key;
import java.util.Date;

public class JwtUtils {
     private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);
     @Value("${app.jwtSecret:Nm53qZ+JLaOL3NFn9kB8t9PbK5g1msXMznUmuKaQTe2R2ghh8KzJeEwLCc+RMP3IzXw+R3aRJj3wNpX7KnUSNA==}")
     private String jwtSecret;

     @Value("${app.jwtExpirationMs:86400000}")
     private int jwtExpirationMs;

     public String generateJwtToken(Authentication authentication){
          
     }

}

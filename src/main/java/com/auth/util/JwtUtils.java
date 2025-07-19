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

import javax.crypto.SecretKey;
import java.util.Date;

@Component
public class JwtUtils {
     private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);
     @Value("${app.jwtSecret:Nm53qZ+JLaOL3NFn9kB8t9PbK5g1msXMznUmuKaQTe2R2ghh8KzJeEwLCc+RMP3IzXw+R3aRJj3wNpX7KnUSNA==}")
     private String jwtSecret;

     @Value("${app.jwtExpirationMs:86400000}")
     private int jwtExpirationMs;

     public String generateJwtToken(Authentication authentication){
          UserDetailsImpl userPrincipal=(UserDetailsImpl)authentication.getPrincipal();
          return Jwts.builder()
                  .subject(userPrincipal.getUsername())
                  .issuedAt(new Date())
                  .expiration(new Date((new Date()).getTime() + jwtExpirationMs))
                  .signWith(key())
                  .compact();

     }
     public String generateTokenFromUsername(String username){
          return Jwts.builder()
                  .subject(username)
                  .issuedAt(new Date())
                  .expiration(new Date((new Date()).getTime() + jwtExpirationMs))
                  .signWith(key())
                  .compact();
     }
     private SecretKey key(){
          return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
     }
     public String getUsernameFromJwtToken(String token){
          return Jwts.parser().verifyWith(key()).build().parseSignedClaims(token).getPayload().getSubject();
     }
     
     public String getUserNameFromJwtToken(String token){
          return getUsernameFromJwtToken(token);
     }
     
     public boolean validateJwtToken(String authToken){
          try{
               Jwts.parser().verifyWith(key()).build().parseSignedClaims(authToken);
               return true;
          }catch(MalformedJwtException e){
               logger.error("Invalid JWT token: {}", e.getMessage());
          }catch(ExpiredJwtException e){
               logger.error("JWT token is expired: {}", e.getMessage());
          }catch(UnsupportedJwtException e){
               logger.error("JWT token is unsupported: {}", e.getMessage());
          }catch(IllegalArgumentException e){
               logger.error("JWT claims string is empty: {}", e.getMessage());
          }
          return false;
     }

}

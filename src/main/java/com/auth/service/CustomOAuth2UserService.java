package com.auth.service;

import com.auth.entity.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

     @Autowired
     @Lazy
     private AuthService authService;

     @Override
     public OAuth2User loadUser(OAuth2UserRequest userRequest) {
          OAuth2User oAuth2User = super.loadUser(userRequest);
          // Save or update user in DB
          User user = authService.processOAuth2User(oAuth2User);
          // You can return a custom OAuth2User if needed
          return oAuth2User;
     }
}
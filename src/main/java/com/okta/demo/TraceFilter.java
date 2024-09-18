package com.okta.demo;


import jakarta.servlet.*;
import lombok.extern.slf4j.Slf4j;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;
import java.io.IOException;
import java.util.Map;
import java.util.Collection;
import java.util.ArrayList;
import java.util.List;

@Component
@Slf4j
public class TraceFilter implements Filter {

    @Override
    public void doFilter(ServletRequest req, ServletResponse res,
            FilterChain chain) throws IOException, ServletException {
        try {
            Authentication currentAuth = SecurityContextHolder.getContext().getAuthentication();

            if (currentAuth instanceof OAuth2AuthenticationToken) {
                OAuth2AuthenticationToken oauth2AuthToken = (OAuth2AuthenticationToken) currentAuth;
                OAuth2User oauth2User = oauth2AuthToken.getPrincipal();
    
                // Extract attributes from OAuth2User
                Map<String, Object> attributes = oauth2User.getAttributes();
                Object groupsObj = attributes.get("groups");
                List<String> groups = new ArrayList<>();
                if (groupsObj instanceof List<?>) {
                    for (Object group : (List<?>) groupsObj) {
                        if (group instanceof String) {
                            groups.add((String) group);
                        }
                    }
                }
                Collection<GrantedAuthority> updatedAuthorities = new ArrayList<>();
                if (groups != null) {
                    for (String group : groups) {
                        updatedAuthorities.add(new SimpleGrantedAuthority(group));
                    }
                }
    
                // Update the authorities
                Authentication newAuth = new OAuth2AuthenticationToken(oauth2User, updatedAuthorities, oauth2AuthToken.getAuthorizedClientRegistrationId());
                SecurityContextHolder.getContext().setAuthentication(newAuth);
            }
            chain.doFilter(req, res);
        } catch (Exception e) {
           e.printStackTrace();
        } finally {
            SecurityContextHolder.clearContext();
        }
    }

}
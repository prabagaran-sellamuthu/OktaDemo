package com.okta.demo;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;

import java.util.Map;

@RestController
public class UserController {

    @GetMapping("/")
    public String getToken(@RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient authorizedClient) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        System.out.println("Authorities: " + authentication.getAuthorities());
        return "Authorities: " + authentication.getAuthorities();
    }
    
    @PreAuthorize("hasAuthority('PAD')")
    @GetMapping("/user")
    public String getUser() {
        return "Hello World";
    }

    @PreAuthorize("hasAuthority('CAD')")
    @GetMapping("/usertest")
    public String getUserTest() {
        return "Hello World";
    }

    @PreAuthorize("hasAuthority('Everyone')")
    @RequestMapping("/oauthinfo")  
    @ResponseBody  
    public String oauthUserInfo(@RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient authorizedClient,  
                              @AuthenticationPrincipal OAuth2User oauth2User) {  
        return  
            "User Name: " + oauth2User.getName() + "<br/>" +  
            "User Authorities: " + oauth2User.getAuthorities() + "<br/>" +  
            "Client Name: " + authorizedClient.getClientRegistration().getClientName() + "<br/>" +  
            this.prettyPrintAttributes(oauth2User.getAttributes());  
    }  

    @PostMapping("/logout")
    public void handleLogout(HttpServletRequest request) {
        // Invalidate the session
        System.out.println("Invalidating session");
        request.getSession().invalidate();
    }

    @PostMapping("/oidc/logout")
    public void handleOidcLogout(HttpServletRequest request) {
        // Invalidate the session
        System.out.println("OIDC back-channel logout received. Invalidating session.");
        request.getSession().invalidate();
    }
  
    private String prettyPrintAttributes(Map<String, Object> attributes) {  
        String acc = "User Attributes: <br/><div style='padding-left:20px'>";  
        for (String key : attributes.keySet()){  
            Object value = attributes.get(key);  
            acc += "<div>"+key + ":&nbsp" + value.toString() + "</div>";  
        }  
        return acc + "</div>";  
    }  
}
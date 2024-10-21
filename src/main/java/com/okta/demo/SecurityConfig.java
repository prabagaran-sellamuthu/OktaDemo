package com.okta.demo;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.session.HttpSessionEventPublisher;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity  // Enables method-level security annotations like @PreAuthorize
public class SecurityConfig {

    @Bean
    public JwtDecoder jwtDecoder() {
        String jwkSetUri = "https://dev-07913094.okta.com/oauth2/default/v1/keys";  // Replace with your Okta JWK Set URI
        return NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(Customizer.withDefaults()) 
            )
            .authorizeHttpRequests(authorizeRequests ->
                authorizeRequests
                    .requestMatchers("/logout", "/oidc/logout").permitAll() 
                    .anyRequest().authenticated()
            )
            .oauth2Login(oauth2 ->
                oauth2
                    .userInfoEndpoint(userInfo ->
                        userInfo
                            .oidcUserService(oidcUserService()) 
                    )
            ).oidcLogout((logout) -> logout
            .backChannel(Customizer.withDefaults())
        );
    
        return http.build();
    }
  
    @Bean
    public OidcUserService oidcUserService() {
        return new OidcUserService();
    }
    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }
}

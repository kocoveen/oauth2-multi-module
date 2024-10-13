package com.example.resourceserver;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.server.resource.web.access.BearerTokenAccessDeniedHandler;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable)
            .authorizeHttpRequests((authorizeRequests) -> {
                authorizeRequests.anyRequest().authenticated();
            })
            .oauth2ResourceServer((resourceServer) -> {
                resourceServer.jwt(Customizer.withDefaults());
            });

        http.oauth2ResourceServer(resourceServer ->
            resourceServer
                .accessDeniedHandler(new BearerTokenAccessDeniedHandler())
                .jwt(jwtConfigurer -> jwtConfigurer
                    .jwtAuthenticationConverter(new CustomPrincipalJwtConvertor())
                )
        );
        return http.build();
    }
}

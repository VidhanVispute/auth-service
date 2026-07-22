package com.skycommerce.auth.config;

import com.skycommerce.auth.filter.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // Disable CSRF (we're using JWT, not sessions)
            .csrf(AbstractHttpConfigurer::disable)
            
            // Stateless - no sessions
            .sessionManagement(session -> 
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            
            // Authorize requests
            .authorizeHttpRequests(auth -> auth
                // Public endpoints - no authentication needed
                .requestMatchers(
                    "/auth/register",
                    "/auth/vendor/register",
                    "/auth/login",
                    "/auth/refresh",
                    "/auth/logout",
                    "/auth/forgot-password",
                    "/auth/reset-password",
                    "/auth/verify-email/**",
                    "/actuator/health",
                    "/actuator/info"
                ).permitAll()
                // All other requests need authentication
                .anyRequest().authenticated()
            )
            // Disable form login (we're using JWT)
            .formLogin(AbstractHttpConfigurer::disable)
            // Disable HTTP Basic (we're using JWT)
            .httpBasic(AbstractHttpConfigurer::disable)
            // Add JWT filter before UsernamePasswordAuthenticationFilter
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
        
        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }
}
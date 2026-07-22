package com.skycommerce.auth.filter;

import com.skycommerce.auth.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                    HttpServletResponse response, 
                                    FilterChain filterChain) 
                                    throws ServletException, IOException {
        
        final String authHeader = request.getHeader("Authorization");
        
        // Check if Authorization header exists and starts with "Bearer "
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            // Extract JWT token from header
            final String jwt = authHeader.substring(7);
            
            // Validate the token
            if (jwtService.validateToken(jwt)) {
                // Extract user information from token
                String email = jwtService.extractEmail(jwt);
                String role = jwtService.extractRole(jwt);
                String userId = jwtService.extractUserId(jwt);
                
                log.debug("Valid JWT token for user: {}, role: {}", email, role);
                
                // Create authentication object
                // In a real app, you might load user details from database
                UsernamePasswordAuthenticationToken authToken = 
                    new UsernamePasswordAuthenticationToken(
                        email, 
                        null, 
                        Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + role))
                    );
                
                // Add additional details to authentication
                authToken.setDetails(userId);
                
                // Set authentication in SecurityContext
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        } catch (Exception e) {
            log.error("Error processing JWT token", e);
        }
        
        filterChain.doFilter(request, response);
    }
}
package com.skycommerce.auth.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/test")
public class TestController {

    @GetMapping("/public")
    public Map<String, String> publicEndpoint() {
        Map<String, String> response = new HashMap<>();
        response.put("message", "This is a PUBLIC endpoint - no auth needed");
        return response;
    }

    @GetMapping("/protected")
    public Map<String, String> protectedEndpoint() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String email = auth.getName();
        
        Map<String, String> response = new HashMap<>();
        response.put("message", "This is a PROTECTED endpoint");
        response.put("user", email);
        response.put("authenticated", "true");
        return response;
    }

    @GetMapping("/admin")
    public Map<String, String> adminEndpoint() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        
        Map<String, String> response = new HashMap<>();
        response.put("message", "ADMIN only endpoint");
        response.put("user", auth.getName());
        response.put("role", auth.getAuthorities().toString());
        return response;
    }
}
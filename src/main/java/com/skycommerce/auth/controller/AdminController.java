package com.skycommerce.auth.controller;

import com.skycommerce.auth.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/admin")
@RequiredArgsConstructor
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {

    private final AuthService authService;

    @PostMapping("/vendors/{vendorId}/approve")
    public ResponseEntity<Void> approveVendor(@PathVariable UUID vendorId) {
        authService.approveVendor(vendorId);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/vendors/{vendorId}/reject")
    public ResponseEntity<Void> rejectVendor(@PathVariable UUID vendorId) {
        authService.rejectVendor(vendorId);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/users/{userId}/suspend")
    public ResponseEntity<Void> suspendUser(@PathVariable UUID userId) {
        authService.suspendUser(userId);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/users/{userId}/ban")
    public ResponseEntity<Void> banUser(@PathVariable UUID userId) {
        authService.banUser(userId);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/users/{userId}/activate")
    public ResponseEntity<Void> activateUser(@PathVariable UUID userId) {
        authService.activateUser(userId);
        return ResponseEntity.ok().build();
    }
}
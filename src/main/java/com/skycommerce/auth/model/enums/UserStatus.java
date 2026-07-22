package com.skycommerce.auth.model.enums;

public enum UserStatus {
    PENDING_VERIFICATION,  // Registered but email not verified
    ACTIVE,                 // Fully active account
    SUSPENDED,              // Temporarily suspended
    BANNED                  // Permanently banned
}
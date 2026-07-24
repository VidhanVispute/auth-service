package com.skycommerce.auth.model.enums;

public enum UserStatus {
    PENDING_VERIFICATION,  // Customer: Email not verified yet
    PENDING_APPROVAL,      // Vendor: Waiting for admin approval
    ACTIVE,                // Fully active account
    SUSPENDED,             // Temporarily suspended by admin
    BANNED                 // Permanently banned
}
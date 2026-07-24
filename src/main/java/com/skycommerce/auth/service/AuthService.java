package com.skycommerce.auth.service;

import com.skycommerce.auth.dto.request.*;
import com.skycommerce.auth.dto.response.AuthResponse;
import com.skycommerce.auth.model.RefreshToken;
import com.skycommerce.auth.model.User;
import com.skycommerce.auth.model.enums.Role;
import com.skycommerce.auth.model.enums.UserStatus;
import com.skycommerce.auth.repository.RefreshTokenRepository;
import com.skycommerce.auth.repository.UserRepository;
import com.skycommerce.auth.util.TokenHashUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDateTime;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    private static final long REFRESH_TOKEN_EXPIRATION_DAYS = 7;

    // ── Registration ──────────────────────────────────────────────────────────

    @Transactional
    public AuthResponse registerCustomer(RegisterRequest request) {
        validateEmailNotTaken(request.getEmail());

        User user = User.builder()
                .email(request.getEmail().toLowerCase())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.CUSTOMER)
                .status(UserStatus.PENDING_VERIFICATION)  // Email verification needed
                .build();

        user = userRepository.save(user);
        log.info("Customer registered: userId={}, email={}", user.getId(), user.getEmail());

        // TODO: Send verification email (we'll implement later)
        // sendVerificationEmail(user);

        return issueTokenPair(user);
    }

    @Transactional
    public AuthResponse registerVendor(VendorRegisterRequest request) {
        validateEmailNotTaken(request.getEmail());

        User user = User.builder()
                .email(request.getEmail().toLowerCase())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.VENDOR)
                .status(UserStatus.PENDING_APPROVAL)  // Admin approval needed
                .build();

        user = userRepository.save(user);
        log.info("Vendor registered: userId={}, email={}, pending approval", 
                user.getId(), user.getEmail());

        // TODO: Notify admins about new vendor registration (we'll implement later)
        // notifyAdminsOfVendorRegistration(user);

        return issueTokenPair(user);
    }

    // ── Login with Proper Status Checks ──────────────────────────────────────

    @Transactional
    public AuthResponse login(LoginRequest request) {
        User user = userRepository.findByEmail(request.getEmail().toLowerCase())
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.UNAUTHORIZED, "Invalid credentials"));

        // Check password
        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new ResponseStatusException(
                    HttpStatus.UNAUTHORIZED, "Invalid credentials");
        }

        // Check account status with proper error messages
        switch (user.getStatus()) {
            case PENDING_VERIFICATION:
                throw new ResponseStatusException(
                        HttpStatus.FORBIDDEN, 
                        "Please verify your email address. A verification link was sent to your email.");
            
            case PENDING_APPROVAL:
                throw new ResponseStatusException(
                        HttpStatus.FORBIDDEN, 
                        "Your vendor account is pending admin approval. You will be notified once approved.");
            
            case SUSPENDED:
                throw new ResponseStatusException(
                        HttpStatus.FORBIDDEN, 
                        "Your account has been suspended. Please contact support for assistance.");
            
            case BANNED:
                throw new ResponseStatusException(
                        HttpStatus.FORBIDDEN, 
                        "Your account has been permanently banned. This action cannot be undone.");
            
            case ACTIVE:
                // Proceed with login
                break;
            
            default:
                throw new ResponseStatusException(
                        HttpStatus.FORBIDDEN, 
                        "Account status not recognized. Please contact support.");
        }

        log.info("User logged in: userId={}, email={}, role={}", 
                user.getId(), user.getEmail(), user.getRole());
        
        return issueTokenPair(user);
    }

    // ── Admin Methods ─────────────────────────────────────────────────────────

    @Transactional
    public void approveVendor(UUID vendorId) {
        User vendor = userRepository.findById(vendorId)
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND, "Vendor not found"));

        if (vendor.getRole() != Role.VENDOR) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST, "User is not a vendor");
        }

        if (vendor.getStatus() != UserStatus.PENDING_APPROVAL) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST, "Vendor is not pending approval");
        }

        vendor.setStatus(UserStatus.ACTIVE);
        userRepository.save(vendor);
        
        log.info("Vendor approved: userId={}, email={}", 
                vendor.getId(), vendor.getEmail());
        
        // TODO: Send approval email to vendor
        // sendVendorApprovalEmail(vendor);
    }

    @Transactional
    public void rejectVendor(UUID vendorId) {
        User vendor = userRepository.findById(vendorId)
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND, "Vendor not found"));

        if (vendor.getRole() != Role.VENDOR) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST, "User is not a vendor");
        }

        if (vendor.getStatus() != UserStatus.PENDING_APPROVAL) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST, "Vendor is not pending approval");
        }

        // Option 1: Delete the vendor account
        // userRepository.delete(vendor);
        
        // Option 2: Set as REJECTED (you'd need to add this status)
        // vendor.setStatus(UserStatus.REJECTED);
        
        // Option 3: Keep as PENDING_APPROVAL but add a note (we'll use this for now)
        log.warn("Vendor rejected: userId={}, email={}", 
                vendor.getId(), vendor.getEmail());
        
        // TODO: Send rejection email to vendor
        // sendVendorRejectionEmail(vendor);
    }

    // ── Email Verification ────────────────────────────────────────────────────

    @Transactional
    public void verifyEmail(String token) {
        // TODO: Implement email verification
        // We'll implement this in Step 8
        log.info("Email verification called with token: {}", token);
    }

    // ── Token Management ──────────────────────────────────────────────────────

    @Transactional
    public AuthResponse refresh(RefreshRequest request) {
        String tokenHash = TokenHashUtil.hash(request.getRefreshToken());

        RefreshToken stored = refreshTokenRepository.findByTokenHash(tokenHash)
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.UNAUTHORIZED, "Invalid refresh token"));

        if (stored.isRevoked()) {
            log.warn("Refresh token reuse detected! Revoking family. userId={}",
                    stored.getUser().getId());
            refreshTokenRepository.revokeAllByFamilyId(stored.getFamilyId());
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,
                    "Token reuse detected. Please log in again.");
        }

        if (stored.isExpired()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,
                    "Refresh token expired. Please log in again.");
        }

        stored.setRevoked(true);
        refreshTokenRepository.save(stored);

        log.info("Token refreshed: userId={}, familyId={}", 
                stored.getUser().getId(), stored.getFamilyId());

        return issueTokenPairInFamily(stored.getUser(), stored.getFamilyId());
    }

    @Transactional
    public void logout(RefreshRequest request) {
        String tokenHash = TokenHashUtil.hash(request.getRefreshToken());

        refreshTokenRepository.findByTokenHash(tokenHash).ifPresent(token -> {
            refreshTokenRepository.revokeAllByFamilyId(token.getFamilyId());
            log.info("User logged out: userId={}, familyId={}", 
                    token.getUser().getId(), token.getFamilyId());
        });
    }

    // ── Private Helpers ───────────────────────────────────────────────────────

    private AuthResponse issueTokenPair(User user) {
        return issueTokenPairInFamily(user, UUID.randomUUID());
    }

    private AuthResponse issueTokenPairInFamily(User user, UUID familyId) {
        String accessToken = jwtService.generateAccessToken(
                user.getId().toString(),
                user.getEmail(),
                user.getRole().name());

        String rawRefreshToken = TokenHashUtil.generateToken();
        String refreshTokenHash = TokenHashUtil.hash(rawRefreshToken);

        RefreshToken refreshToken = RefreshToken.builder()
                .user(user)
                .tokenHash(refreshTokenHash)
                .familyId(familyId)
                .expiresAt(LocalDateTime.now().plusDays(REFRESH_TOKEN_EXPIRATION_DAYS))
                .revoked(false)
                .build();

        refreshTokenRepository.save(refreshToken);

        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(rawRefreshToken)
                .tokenType("Bearer")
                .expiresIn(900)
                .role(user.getRole().name())
                .userId(user.getId().toString())
                .build();
    }

    private void validateEmailNotTaken(String email) {
        if (userRepository.existsByEmail(email.toLowerCase())) {
            throw new ResponseStatusException(
                    HttpStatus.CONFLICT, "Email already registered");
        }
    }

    // ── Admin Controller Methods (to be added) ──────────────────────────────

    public void suspendUser(UUID userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND, "User not found"));

        if (user.getStatus() == UserStatus.ACTIVE) {
            user.setStatus(UserStatus.SUSPENDED);
            userRepository.save(user);
            log.info("User suspended: userId={}, email={}", 
                    user.getId(), user.getEmail());
        }
    }

    public void banUser(UUID userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND, "User not found"));

        user.setStatus(UserStatus.BANNED);
        userRepository.save(user);
        log.info("User banned: userId={}, email={}", 
                user.getId(), user.getEmail());
    }

    public void activateUser(UUID userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND, "User not found"));

        if (user.getStatus() == UserStatus.PENDING_VERIFICATION ||
            user.getStatus() == UserStatus.SUSPENDED) {
            user.setStatus(UserStatus.ACTIVE);
            userRepository.save(user);
            log.info("User activated: userId={}, email={}", 
                    user.getId(), user.getEmail());
        }
    }
}
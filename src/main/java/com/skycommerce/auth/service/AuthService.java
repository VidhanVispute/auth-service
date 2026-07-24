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
                .status(UserStatus.ACTIVE)
                .build();

        user = userRepository.save(user);
        log.info("Customer registered: userId={}, email={}", user.getId(), user.getEmail());

        return issueTokenPair(user);
    }

    @Transactional
    public AuthResponse registerVendor(VendorRegisterRequest request) {
        validateEmailNotTaken(request.getEmail());

        User user = User.builder()
                .email(request.getEmail().toLowerCase())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.VENDOR)
                .status(UserStatus.PENDING_VERIFICATION)  // Vendors need admin approval
                .build();

        user = userRepository.save(user);
        log.info("Vendor registered: userId={}, email={}", user.getId(), user.getEmail());

        return issueTokenPair(user);
    }

    // ── Login ─────────────────────────────────────────────────────────────────

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

        // Check account status - More specific messages
    switch (user.getStatus()) {
        case PENDING_VERIFICATION:
            throw new ResponseStatusException(
                    HttpStatus.FORBIDDEN, 
                    "Please verify your email address. A verification link was sent to your email.");
        case SUSPENDED:
            throw new ResponseStatusException(
                    HttpStatus.FORBIDDEN, 
                    "Your account has been suspended. Please contact support.");
        case BANNED:
            throw new ResponseStatusException(
                    HttpStatus.FORBIDDEN, 
                    "Your account has been banned. This action cannot be undone.");
        case ACTIVE:
            // Proceed with login
            break;
        default:
            throw new ResponseStatusException(
                    HttpStatus.FORBIDDEN, 
                    "Account status not recognized. Please contact support.");
    }


        log.info("User logged in: userId={}, email={}", user.getId(), user.getEmail());
        return issueTokenPair(user);
    }

    // ── Token Refresh ─────────────────────────────────────────────────────────

    @Transactional
    public AuthResponse refresh(RefreshRequest request) {
        String tokenHash = TokenHashUtil.hash(request.getRefreshToken());

        RefreshToken stored = refreshTokenRepository.findByTokenHash(tokenHash)
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.UNAUTHORIZED, "Invalid refresh token"));

        // Reuse detection - if this token was already revoked, it's theft
        if (stored.isRevoked()) {
            log.warn("Refresh token reuse detected! Revoking family. userId={}",
                    stored.getUser().getId());
            refreshTokenRepository.revokeAllByFamilyId(stored.getFamilyId());
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,
                    "Token reuse detected. Please log in again.");
        }

        // Check if token is expired
        if (stored.isExpired()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,
                    "Refresh token expired. Please log in again.");
        }

        // Rotate: revoke current token, issue new token in same family
        stored.setRevoked(true);
        refreshTokenRepository.save(stored);

        log.info("Token refreshed: userId={}, familyId={}", 
                stored.getUser().getId(), stored.getFamilyId());

        return issueTokenPairInFamily(stored.getUser(), stored.getFamilyId());
    }

    // ── Logout ────────────────────────────────────────────────────────────────

    @Transactional
    public void logout(RefreshRequest request) {
        String tokenHash = TokenHashUtil.hash(request.getRefreshToken());

        refreshTokenRepository.findByTokenHash(tokenHash).ifPresent(token -> {
            // Revoke entire family - logs out all devices sharing this session
            refreshTokenRepository.revokeAllByFamilyId(token.getFamilyId());
            log.info("User logged out: userId={}, familyId={}", 
                    token.getUser().getId(), token.getFamilyId());
        });
        
        // Silent success if token not found - don't reveal whether it existed
    }

    // ── Private Helpers ───────────────────────────────────────────────────────

    private AuthResponse issueTokenPair(User user) {
        // New login = new family
        return issueTokenPairInFamily(user, UUID.randomUUID());
    }

    private AuthResponse issueTokenPairInFamily(User user, UUID familyId) {
        // Generate access token
        String accessToken = jwtService.generateAccessToken(
                user.getId().toString(),
                user.getEmail(),
                user.getRole().name());

        // Generate refresh token
        String rawRefreshToken = TokenHashUtil.generateToken();
        String refreshTokenHash = TokenHashUtil.hash(rawRefreshToken);

        // Save refresh token to database
        RefreshToken refreshToken = RefreshToken.builder()
                .user(user)
                .tokenHash(refreshTokenHash)
                .familyId(familyId)
                .expiresAt(LocalDateTime.now().plusDays(REFRESH_TOKEN_EXPIRATION_DAYS))
                .revoked(false)
                .build();

        refreshTokenRepository.save(refreshToken);

        // Return response
        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(rawRefreshToken)  // Raw token sent to client
                .tokenType("Bearer")
                .expiresIn(900)  // 15 minutes in seconds
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
}
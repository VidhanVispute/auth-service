package com.skycommerce.auth.config;

import com.skycommerce.auth.model.User;
import com.skycommerce.auth.model.enums.Role;
import com.skycommerce.auth.model.enums.UserStatus;
import com.skycommerce.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class DataInitializer implements ApplicationRunner {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Value("${app.admin.email:admin@skycommerce.com}")
    private String adminEmail;

    @Value("${app.admin.password:Admin@SkyCommerce#2026}")
    private String adminPassword;

    @Override
    public void run(ApplicationArguments args) {
        seedAdminUser();
    }

    private void seedAdminUser() {
        if (userRepository.existsByEmail(adminEmail)) {
            log.info("Admin user already exists - skipping seed");
            return;
        }

        User admin = User.builder()
                .email(adminEmail)
                .password(passwordEncoder.encode(adminPassword))
                .role(Role.ADMIN)
                .status(UserStatus.ACTIVE)
                .build();

        userRepository.save(admin);
        log.info("Admin user seeded successfully: {}", adminEmail);
    }
}
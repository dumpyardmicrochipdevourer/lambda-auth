package com.microchip.lambda_auth.service.util;

import com.microchip.lambda_auth.config.AdminProperties;
import com.microchip.lambda_auth.domain.Role;
import com.microchip.lambda_auth.domain.User;
import com.microchip.lambda_auth.domain.repo.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class AdminBootstrap implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(AdminBootstrap.class);

    private final AdminProperties properties;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final CredentialsValidator validator;

    public AdminBootstrap(
            AdminProperties properties,
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            CredentialsValidator validator) {
        this.properties = properties;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.validator = validator;
    }

    @Override
    public void run(ApplicationArguments args) {
        if (isBlank(properties.username()) || isBlank(properties.password())) {
            return;
        }
        if (userRepository.existsByRole(Role.ADMIN)) {
            return;
        }
        validator.validate(properties.username(), properties.password());
        userRepository.save(new User(properties.username(), passwordEncoder.encode(properties.password()), Role.ADMIN));
        log.info("создан первый админ {}", properties.username());
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}

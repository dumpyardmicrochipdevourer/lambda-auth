package com.microchip.lambda_auth.domain.repo;

import java.util.Optional;
import java.util.UUID;

import com.microchip.lambda_auth.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, UUID> {

    Optional<User> findByUsernameIgnoreCase(String username);

    boolean existsByUsernameIgnoreCase(String username);
}

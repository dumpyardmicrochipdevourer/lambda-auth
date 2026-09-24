package com.microchip.lambda_auth.domain.repo;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import com.microchip.lambda_auth.domain.Invite;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface InviteRepository extends JpaRepository<Invite, UUID> {

    Optional<Invite> findByCode(String code);

    List<Invite> findByCreatedByOrderByCreatedAtDesc(UUID createdBy);

    @Modifying
    @Query("""
            update Invite i set i.usedBy = :userId, i.usedAt = :now
            where i.code = :code and i.usedAt is null and i.expiresAt > :now
            """)
    int redeem(@Param("code") String code, @Param("userId") UUID userId, @Param("now") Instant now);
}

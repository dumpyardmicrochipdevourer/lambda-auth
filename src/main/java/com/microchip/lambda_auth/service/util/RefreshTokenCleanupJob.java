package com.microchip.lambda_auth.service.util;

import com.microchip.lambda_auth.domain.repo.RefreshTokenRepository;
import java.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
public class RefreshTokenCleanupJob {

    private static final Logger log = LoggerFactory.getLogger(RefreshTokenCleanupJob.class);

    private final RefreshTokenRepository refreshTokenRepository;

    public RefreshTokenCleanupJob(RefreshTokenRepository refreshTokenRepository) {
        this.refreshTokenRepository = refreshTokenRepository;
    }

    @Scheduled(fixedDelayString = "PT1H", initialDelayString = "PT1M")
    @Transactional
    public void sweep() {
        int deleted = refreshTokenRepository.deleteExpired(Instant.now());
        if (deleted > 0) {
            log.info("удалено протухших refresh-токенов: {}", deleted);
        }
    }
}

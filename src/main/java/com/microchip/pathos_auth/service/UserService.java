package com.microchip.pathos_auth.service;

import com.microchip.pathos_auth.domain.User;
import com.microchip.pathos_auth.domain.dto.UserView;
import com.microchip.pathos_auth.domain.repo.RefreshTokenRepository;
import com.microchip.pathos_auth.domain.repo.UserRepository;
import com.microchip.pathos_auth.service.exceptions.UserNotFoundException;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;

    public UserService(UserRepository userRepository, RefreshTokenRepository refreshTokenRepository) {
        this.userRepository = userRepository;
        this.refreshTokenRepository = refreshTokenRepository;
    }

    public UserView get(UUID id) {
        return UserView.of(find(id));
    }

    public List<UserView> list() {
        return userRepository.findAll(Sort.by("createdAt")).stream().map(UserView::of).toList();
    }

    @Transactional
    public UserView setEnabled(UUID actorId, UUID id, boolean enabled) {
        if (actorId.equals(id) && !enabled) {
            throw new IllegalArgumentException("нельзя отключить самого себя");
        }
        User user = find(id);
        user.setEnabled(enabled);
        if (!enabled) {
            refreshTokenRepository.revokeAll(id, Instant.now());
        }
        return UserView.of(user);
    }

    private User find(UUID id) {
        return userRepository.findById(id).orElseThrow(() -> new UserNotFoundException(id));
    }
}

package com.microchip.lambda_auth.service;

import com.microchip.lambda_auth.domain.Invite;
import com.microchip.lambda_auth.domain.User;
import com.microchip.lambda_auth.domain.dto.InviteView;
import com.microchip.lambda_auth.domain.repo.InviteRepository;
import com.microchip.lambda_auth.domain.repo.UserRepository;
import com.microchip.lambda_auth.service.util.InviteCodeGenerator;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.stream.Collectors;
import org.springframework.stereotype.Service;

@Service
public class InviteService {

    private final InviteRepository inviteRepository;
    private final UserRepository userRepository;
    private final InviteCodeGenerator codeGenerator;

    public InviteService(
            InviteRepository inviteRepository,
            UserRepository userRepository,
            InviteCodeGenerator codeGenerator) {
        this.inviteRepository = inviteRepository;
        this.userRepository = userRepository;
        this.codeGenerator = codeGenerator;
    }

    public InviteView create(UUID creatorId, Duration ttl) {
        Invite invite = inviteRepository.save(new Invite(codeGenerator.generate(), creatorId, Instant.now().plus(ttl)));
        return view(invite, null);
    }

    public List<InviteView> list(UUID creatorId) {
        List<Invite> invites = inviteRepository.findByCreatedByOrderByCreatedAtDesc(creatorId);
        List<UUID> usedBy = invites.stream().map(Invite::getUsedBy).filter(Objects::nonNull).toList();
        Map<UUID, String> usernames = userRepository.findAllById(usedBy).stream()
                .collect(Collectors.toMap(User::getId, User::getUsername));
        return invites.stream().map(i -> view(i, usernames.get(i.getUsedBy()))).toList();
    }

    private static InviteView view(Invite invite, String usedBy) {
        return new InviteView(invite.getCode(), invite.getCreatedAt(), invite.getExpiresAt(), usedBy, invite.getUsedAt());
    }
}

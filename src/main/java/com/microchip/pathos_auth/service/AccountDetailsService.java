package com.microchip.pathos_auth.service;

import com.microchip.pathos_auth.domain.User;
import com.microchip.pathos_auth.domain.repo.UserRepository;
import com.microchip.pathos_auth.service.util.LoginThrottle;
import java.util.List;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

// Accounts for the sign-in page. The principal is named by the account id, not by the
// username: that name becomes `sub` in every token, and the same id is what the API tokens carry.
@Service
public class AccountDetailsService implements UserDetailsService {

    private final UserRepository users;
    private final LoginThrottle throttle;

    public AccountDetailsService(UserRepository users, LoginThrottle throttle) {
        this.users = users;
        this.throttle = throttle;
    }

    @Override
    public UserDetails loadUserByUsername(String username) {
        User user = users.findByUsernameIgnoreCase(username)
                .orElseThrow(() -> new UsernameNotFoundException(username));
        return org.springframework.security.core.userdetails.User
                .withUsername(user.getId().toString())
                .password(user.getPasswordHash())
                .disabled(!user.isEnabled())
                // too many misses: the right password does not help either until the name has rested
                .accountLocked(throttle.blocked(username))
                .authorities(List.of(new SimpleGrantedAuthority("ROLE_" + user.getRole().name())))
                .build();
    }
}

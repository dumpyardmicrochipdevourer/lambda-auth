package com.microchip.pathos_auth.config;

import java.util.List;
import java.util.Map;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

// Services that offer "sign in with pathos". The key is the client id.
@ConfigurationProperties(prefix = "pathos.auth.oauth")
public record OAuthProperties(@DefaultValue Map<String, Client> clients) {

    // access: the name an account must have in its access list to sign in to this service;
    // empty lets every account in
    public record Client(String secret, List<String> redirectUris, String access) {
    }

    public List<String> services() {
        return clients.values().stream().map(Client::access).filter(a -> a != null && !a.isBlank())
                .distinct().sorted().toList();
    }
}

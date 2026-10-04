package com.microchip.pathos_auth.config;

import com.microchip.pathos_auth.domain.User;
import com.microchip.pathos_auth.domain.repo.UserRepository;
import com.microchip.pathos_auth.service.util.LoginThrottle;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Consumer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationValidator;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

// "Sign in with pathos": the OAuth2 / OpenID Connect side. A service sends the visitor here,
// the visitor signs in on this domain (or already has), and comes back with a code the service
// exchanges for tokens. The API for pathos' own pages stays in SecurityConfig, untouched.
@Configuration
public class OAuthConfiguration {

    static final String LOGIN = "/login";

    @Bean
    @Order(1)
    SecurityFilterChain authorizationServerChain(HttpSecurity http, UserRepository users, OAuthProperties oauth)
            throws Exception {
        OAuth2AuthorizationServerConfigurer server = new OAuth2AuthorizationServerConfigurer();
        return http
                .securityMatcher(server.getEndpointsMatcher())
                .with(server, s -> s
                        .authorizationEndpoint(a -> a.authenticationProviders(letInOnlyTheAllowed(users, oauth)))
                        .oidc(o -> o.userInfoEndpoint(u -> u.userInfoMapper(context ->
                                userInfo(users, context.getAuthorization().getPrincipalName())))))
                .authorizeHttpRequests(a -> a.anyRequest().authenticated())
                .csrf(c -> c.ignoringRequestMatchers(server.getEndpointsMatcher()))
                // a browser is sent to the sign-in page, a service gets a plain 401
                .exceptionHandling(e -> e.defaultAuthenticationEntryPointFor(
                        new LoginUrlAuthenticationEntryPoint(LOGIN), new MediaTypeRequestMatcher(MediaType.TEXT_HTML)))
                .oauth2ResourceServer(o -> o.jwt(Customizer.withDefaults()))
                .build();
    }

    @Bean
    @Order(2)
    SecurityFilterChain signInChain(HttpSecurity http, LoginThrottle throttle) throws Exception {
        SimpleUrlAuthenticationFailureHandler failed = new SimpleUrlAuthenticationFailureHandler(LOGIN + "?error");
        return http
                .securityMatcher(LOGIN, "/logout", "/", "/auth.css")
                .authorizeHttpRequests(a -> a.anyRequest().permitAll())
                .formLogin(f -> f
                        .loginPage(LOGIN)
                        .successHandler((request, response, authentication) -> {
                            throttle.succeeded(request.getParameter("username"));
                            new org.springframework.security.web.authentication
                                    .SavedRequestAwareAuthenticationSuccessHandler()
                                    .onAuthenticationSuccess(request, response, authentication);
                        })
                        .failureHandler((request, response, exception) -> {
                            if (exception instanceof BadCredentialsException) {
                                throttle.failed(request.getParameter("username"));
                            }
                            failed.onAuthenticationFailure(request, response, exception);
                        }))
                .logout(l -> l.logoutSuccessUrl(LOGIN + "?out"))
                .build();
    }

    @Bean
    RegisteredClientRepository registeredClients(OAuthProperties oauth, PasswordEncoder encoder) {
        List<RegisteredClient> clients = new ArrayList<>();
        oauth.clients().forEach((id, client) -> {
            if (client.secret() == null || client.secret().isBlank() || client.redirectUris() == null) {
                throw new IllegalStateException("oauth client " + id + " needs a secret and redirect-uris");
            }
            clients.add(RegisteredClient.withId(id)
                    .clientId(id)
                    .clientSecret(encoder.encode(client.secret()))
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .redirectUris(uris -> uris.addAll(client.redirectUris()))
                    .scope(OidcScopes.OPENID)
                    .scope(OidcScopes.PROFILE)
                    // these are pathos' own services: nobody is asked to "allow" them
                    .clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build())
                    .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofMinutes(10)).build())
                    .build());
        });
        // the repository refuses to be empty; a service that can never be redirected to is harmless
        if (clients.isEmpty()) {
            clients.add(RegisteredClient.withId("none").clientId("none")
                    .clientSecret(encoder.encode(UUID.randomUUID().toString()))
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .redirectUri("http://127.0.0.1/none").build());
        }
        return new InMemoryRegisteredClientRepository(clients);
    }

    @Bean
    AuthorizationServerSettings authorizationServerSettings(JwtProperties properties) {
        return AuthorizationServerSettings.builder().issuer(properties.issuer()).build();
    }

    @Bean
    JWKSource<SecurityContext> jwkSource(RSAKey jwtKey) {
        return new ImmutableJWKSet<>(new JWKSet(jwtKey));
    }

    // the same claims the API tokens carry, so a service reads one shape whatever the way in
    @Bean
    OAuth2TokenCustomizer<JwtEncodingContext> accountClaims(UserRepository users) {
        return context -> account(users, context.getPrincipal().getName()).ifPresent(user -> context.getClaims()
                .claim("username", user.getUsername())
                .claim("preferred_username", user.getUsername())
                .claim("role", user.getRole().name())
                .claim("access", user.getAccess()));
    }

    private static OidcUserInfo userInfo(UserRepository users, String principal) {
        User user = account(users, principal).orElseThrow();
        return OidcUserInfo.builder()
                .subject(user.getId().toString())
                .preferredUsername(user.getUsername())
                .claim("role", user.getRole().name())
                .claim("access", user.getAccess())
                .build();
    }

    // An account signs in to a service only if an admin let it in. The refusal goes back
    // to the service as access_denied, so it can say so in its own words.
    private static Consumer<List<org.springframework.security.authentication.AuthenticationProvider>>
            letInOnlyTheAllowed(UserRepository users, OAuthProperties oauth) {
        Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> allowed = context -> {
            OAuth2AuthorizationCodeRequestAuthenticationToken request = context.getAuthentication();
            if (!(request.getPrincipal() instanceof Authentication principal) || !principal.isAuthenticated()
                    || principal instanceof org.springframework.security.authentication.AnonymousAuthenticationToken) {
                return;
            }
            OAuthProperties.Client client = oauth.clients().get(context.getRegisteredClient().getClientId());
            String service = client == null ? null : client.access();
            boolean ok = account(users, principal.getName()).filter(User::isEnabled)
                    .map(u -> u.mayEnter(service == null || service.isBlank() ? null : service)).orElse(false);
            if (!ok) {
                throw new OAuth2AuthorizationCodeRequestAuthenticationException(
                        new OAuth2Error(OAuth2ErrorCodes.ACCESS_DENIED, "the account is not let into this service", null),
                        request);
            }
        };
        return providers -> providers.forEach(provider -> {
            if (provider instanceof OAuth2AuthorizationCodeRequestAuthenticationProvider codeRequests) {
                codeRequests.setAuthenticationValidator(
                        new OAuth2AuthorizationCodeRequestAuthenticationValidator().andThen(allowed));
            }
        });
    }

    private static Optional<User> account(UserRepository users, String principal) {
        try {
            return users.findById(UUID.fromString(principal));
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
    }
}

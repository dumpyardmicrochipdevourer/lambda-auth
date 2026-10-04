package com.microchip.pathos_auth.web;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.jayway.jsonpath.JsonPath;
import com.microchip.pathos_auth.IntegrationTest;
import com.microchip.pathos_auth.config.JwtProperties;
import com.microchip.pathos_auth.domain.Invite;
import com.microchip.pathos_auth.domain.Role;
import com.microchip.pathos_auth.domain.User;
import com.microchip.pathos_auth.domain.repo.InviteRepository;
import com.microchip.pathos_auth.domain.repo.UserRepository;
import com.microchip.pathos_auth.service.JwtService;
import jakarta.persistence.EntityManager;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.transaction.annotation.Transactional;

@AutoConfigureMockMvc
@Transactional
class InviteControllerTest extends IntegrationTest {

    @Autowired MockMvc mvc;
    @Autowired UserRepository users;
    @Autowired InviteRepository invites;
    @Autowired JwtService jwtService;
    @Autowired JwtEncoder encoder;
    @Autowired JwtProperties properties;
    @Autowired EntityManager em;

    @Test
    void adminCreatesInviteWithDefaultTtl() throws Exception {
        User admin = user(Role.ADMIN);

        String body = mvc.perform(post("/api/invites").header(HttpHeaders.AUTHORIZATION, bearer(admin)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").isString())
                .andExpect(jsonPath("$.usedBy").doesNotExist())
                .andReturn().getResponse().getContentAsString();

        Invite invite = invites.findByCode(JsonPath.<String>read(body, "$.code")).orElseThrow();
        assertTrue(invite.getCreatedBy().equals(admin.getId()));
        assertTrue(invite.getExpiresAt().isAfter(Instant.now().plus(Duration.ofDays(6))));
        assertTrue(invite.getExpiresAt().isBefore(Instant.now().plus(Duration.ofDays(8))));
    }

    @Test
    void ttlDaysIsBounded() throws Exception {
        String auth = bearer(user(Role.ADMIN));

        mvc.perform(createWithTtl(auth, 0)).andExpect(status().isBadRequest());
        mvc.perform(createWithTtl(auth, 31)).andExpect(status().isBadRequest());
        mvc.perform(createWithTtl(auth, 30)).andExpect(status().isOk());
    }

    @Test
    void createdInviteRegistersUserAndListShowsWhoUsedIt() throws Exception {
        String auth = bearer(user(Role.ADMIN));
        String code = JsonPath.read(
                mvc.perform(post("/api/invites").header(HttpHeaders.AUTHORIZATION, auth))
                        .andReturn().getResponse().getContentAsString(), "$.code");
        String username = name();

        mvc.perform(post("/api/auth/register").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"inviteCode\":\"%s\",\"username\":\"%s\",\"password\":\"correct horse\"}"
                                .formatted(code, username)))
                .andExpect(status().isOk());
        em.flush();
        em.clear();

        mvc.perform(get("/api/invites").header(HttpHeaders.AUTHORIZATION, auth))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].code").value(code))
                .andExpect(jsonPath("$[0].usedBy").value(username))
                .andExpect(jsonPath("$[0].usedAt").isNotEmpty());
    }

    @Test
    void listShowsOnlyOwnInvitesNewestFirst() throws Exception {
        String mine = bearer(user(Role.ADMIN));
        String other = bearer(user(Role.ADMIN));
        mvc.perform(post("/api/invites").header(HttpHeaders.AUTHORIZATION, other));
        String first = created(mine);
        String second = created(mine);

        mvc.perform(get("/api/invites").header(HttpHeaders.AUTHORIZATION, mine))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(2))
                .andExpect(jsonPath("$[0].code").value(second))
                .andExpect(jsonPath("$[1].code").value(first));
    }

    @Test
    void regularUserIsForbidden() throws Exception {
        String auth = bearer(user(Role.USER));

        mvc.perform(post("/api/invites").header(HttpHeaders.AUTHORIZATION, auth)).andExpect(status().isForbidden());
        mvc.perform(get("/api/invites").header(HttpHeaders.AUTHORIZATION, auth)).andExpect(status().isForbidden());
    }

    @Test
    void missingAndBrokenTokensAreUnauthorized() throws Exception {
        User admin = user(Role.ADMIN);
        String valid = jwtService.issue(admin);
        String tampered = valid.substring(0, valid.length() - 4) + "AAAA";
        String expired = expiredToken(admin);
        String foreignIssuer = tokenWith(new JwtProperties(
                properties.privateKeyPath(), "https://evil.test", properties.keyId(), Duration.ofMinutes(5)), admin);

        mvc.perform(get("/api/invites")).andExpect(status().isUnauthorized());
        for (String token : new String[] {"garbage", tampered, expired, foreignIssuer}) {
            mvc.perform(get("/api/invites").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                    .andExpect(status().isUnauthorized());
        }
    }

    private String created(String auth) throws Exception {
        return JsonPath.read(
                mvc.perform(post("/api/invites").header(HttpHeaders.AUTHORIZATION, auth))
                        .andReturn().getResponse().getContentAsString(), "$.code");
    }

    private static MockHttpServletRequestBuilder createWithTtl(String auth, int ttlDays) {
        return post("/api/invites").header(HttpHeaders.AUTHORIZATION, auth)
                .contentType(MediaType.APPLICATION_JSON).content("{\"ttlDays\":%d}".formatted(ttlDays));
    }

    private String expiredToken(User user) {
        Instant issuedAt = Instant.now().minus(Duration.ofHours(1));
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(properties.issuer())
                .subject(user.getId().toString())
                .issuedAt(issuedAt)
                .expiresAt(issuedAt.plus(Duration.ofMinutes(10)))
                .claim("role", user.getRole().name())
                .build();
        JwsHeader header = JwsHeader.with(SignatureAlgorithm.RS256).keyId(properties.keyId()).build();
        return encoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
    }

    private String tokenWith(JwtProperties custom, User user) {
        return new JwtService(encoder, custom).issue(user);
    }

    private String bearer(User user) {
        return "Bearer " + jwtService.issue(user);
    }

    private User user(Role role) {
        return users.save(new User(name(), "hash", role));
    }

    private static String name() {
        return "u" + UUID.randomUUID().toString().substring(0, 8);
    }
}

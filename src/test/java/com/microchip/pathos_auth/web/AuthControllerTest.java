package com.microchip.pathos_auth.web;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.jayway.jsonpath.JsonPath;
import com.microchip.pathos_auth.IntegrationTest;
import com.microchip.pathos_auth.domain.Invite;
import com.microchip.pathos_auth.domain.Role;
import com.microchip.pathos_auth.domain.User;
import com.microchip.pathos_auth.domain.repo.InviteRepository;
import com.microchip.pathos_auth.domain.repo.UserRepository;
import com.microchip.pathos_auth.service.util.InviteCodeGenerator;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

@AutoConfigureMockMvc
class AuthControllerTest extends IntegrationTest {

    @Autowired MockMvc mvc;
    @Autowired UserRepository users;
    @Autowired InviteRepository invites;
    @Autowired InviteCodeGenerator codes;
    @Autowired PasswordEncoder encoder;

    @Test
    void loginReturnsTokenPair() throws Exception {
        User user = user();

        mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"%s\",\"password\":\"secret\"}".formatted(user.getUsername())))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.refreshToken").isNotEmpty())
                .andExpect(jsonPath("$.expiresIn").value(600));
    }

    @Test
    void wrongPasswordIs401() throws Exception {
        User user = user();

        mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"%s\",\"password\":\"wrong\"}".formatted(user.getUsername())))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void blankUsernameIs400() throws Exception {
        mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\" \",\"password\":\"secret\"}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void logoutReturns204AndKillsRefreshToken() throws Exception {
        User user = user();
        String body = mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"%s\",\"password\":\"secret\"}".formatted(user.getUsername())))
                .andReturn().getResponse().getContentAsString();
        String refreshRequest = "{\"refreshToken\":\"%s\"}".formatted(JsonPath.<String>read(body, "$.refreshToken"));

        mvc.perform(post("/api/auth/logout").contentType(MediaType.APPLICATION_JSON).content(refreshRequest))
                .andExpect(status().isNoContent());
        mvc.perform(post("/api/auth/refresh").contentType(MediaType.APPLICATION_JSON).content(refreshRequest))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void registerWithValidInviteReturnsTokenPair() throws Exception {
        mvc.perform(register(invite().getCode(), name(), "correct horse"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.refreshToken").isNotEmpty());
    }

    @Test
    void registerWithUnknownInviteIs403() throws Exception {
        mvc.perform(register("nope", name(), "correct horse")).andExpect(status().isForbidden());
    }

    @Test
    void registerWithTakenUsernameIs409() throws Exception {
        String username = name();
        mvc.perform(register(invite().getCode(), username, "correct horse")).andExpect(status().isOk());

        mvc.perform(register(invite().getCode(), username, "correct horse")).andExpect(status().isConflict());
    }

    @Test
    void registerWithWeakPasswordIs400() throws Exception {
        mvc.perform(register(invite().getCode(), name(), "short")).andExpect(status().isBadRequest());
    }

    @Test
    void registerWithoutInviteIs400() throws Exception {
        mvc.perform(post("/api/auth/register").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"%s\",\"password\":\"correct horse\"}".formatted(name())))
                .andExpect(status().isBadRequest());
    }

    @Test
    void protectedPathWithoutTokenIs401() throws Exception {
        mvc.perform(get("/api/anything")).andExpect(status().isUnauthorized());
    }

    @Test
    void jwksIsPublic() throws Exception {
        mvc.perform(get("/.well-known/jwks.json"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys[0].kid").value("pathos-auth-1"));
    }

    @Test
    void meReturnsCurrentUser() throws Exception {
        User user = user();
        String access = JsonPath.read(login(user.getUsername(), "secret"), "$.accessToken");

        mvc.perform(get("/api/auth/me").header("Authorization", "Bearer " + access))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value(user.getUsername()))
                .andExpect(jsonPath("$.role").value("USER"))
                .andExpect(jsonPath("$.passwordHash").doesNotExist());
    }

    @Test
    void changePasswordRevokesOldSessionsAndAcceptsNewPassword() throws Exception {
        User user = user();
        String body = login(user.getUsername(), "secret");
        String access = JsonPath.read(body, "$.accessToken");
        String oldRefresh = "{\"refreshToken\":\"%s\"}".formatted(JsonPath.<String>read(body, "$.refreshToken"));

        mvc.perform(post("/api/auth/password").header("Authorization", "Bearer " + access)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"currentPassword\":\"secret\",\"newPassword\":\"correct horse\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.refreshToken").isNotEmpty());

        mvc.perform(post("/api/auth/refresh").contentType(MediaType.APPLICATION_JSON).content(oldRefresh))
                .andExpect(status().isUnauthorized());
        mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"%s\",\"password\":\"correct horse\"}".formatted(user.getUsername())))
                .andExpect(status().isOk());
    }

    @Test
    void changePasswordWithWrongCurrentIs401() throws Exception {
        User user = user();
        String access = JsonPath.read(login(user.getUsername(), "secret"), "$.accessToken");

        mvc.perform(post("/api/auth/password").header("Authorization", "Bearer " + access)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"currentPassword\":\"nope\",\"newPassword\":\"correct horse\"}"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void changePasswordToWeakIs400() throws Exception {
        User user = user();
        String access = JsonPath.read(login(user.getUsername(), "secret"), "$.accessToken");

        mvc.perform(post("/api/auth/password").header("Authorization", "Bearer " + access)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"currentPassword\":\"secret\",\"newPassword\":\"short\"}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void healthIsPublic() throws Exception {
        mvc.perform(get("/actuator/health")).andExpect(status().isOk());
    }

    @Test
    void metricsExposeAccounts() throws Exception {
        user();

        String body = mvc.perform(get("/actuator/prometheus")).andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        org.junit.jupiter.api.Assertions.assertTrue(body.contains("pathos_auth_users"));
        org.junit.jupiter.api.Assertions.assertTrue(body.contains("pathos_auth_sessions"));
    }

    private String login(String username, String password) throws Exception {
        return mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"%s\",\"password\":\"%s\"}".formatted(username, password)))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
    }

    private User user() {
        return users.save(new User(name(), encoder.encode("secret"), Role.USER));
    }

    private Invite invite() {
        User creator = users.save(new User(name(), "hash", Role.USER));
        return invites.save(new Invite(codes.generate(), creator.getId(), Instant.now().plus(Duration.ofDays(1))));
    }

    private static MockHttpServletRequestBuilder register(String inviteCode, String username, String password) {
        return post("/api/auth/register").contentType(MediaType.APPLICATION_JSON)
                .content("{\"inviteCode\":\"%s\",\"username\":\"%s\",\"password\":\"%s\"}"
                        .formatted(inviteCode, username, password));
    }

    private static String name() {
        return "u" + UUID.randomUUID().toString().substring(0, 8);
    }
}

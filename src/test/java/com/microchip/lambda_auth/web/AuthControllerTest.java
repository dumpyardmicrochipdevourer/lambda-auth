package com.microchip.lambda_auth.web;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.jayway.jsonpath.JsonPath;
import com.microchip.lambda_auth.IntegrationTest;
import com.microchip.lambda_auth.domain.Role;
import com.microchip.lambda_auth.domain.User;
import com.microchip.lambda_auth.domain.repo.UserRepository;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;

@AutoConfigureMockMvc
class AuthControllerTest extends IntegrationTest {

    @Autowired MockMvc mvc;
    @Autowired UserRepository users;
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
    void protectedPathWithoutTokenIs401() throws Exception {
        mvc.perform(get("/api/anything")).andExpect(status().isUnauthorized());
    }

    @Test
    void jwksIsPublic() throws Exception {
        mvc.perform(get("/.well-known/jwks.json"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys[0].kid").value("lambda-auth-1"));
    }

    private User user() {
        String username = "u" + UUID.randomUUID().toString().substring(0, 8);
        return users.save(new User(username, encoder.encode("secret"), Role.USER));
    }
}

package com.microchip.lambda_auth.web;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.jayway.jsonpath.JsonPath;
import com.microchip.lambda_auth.IntegrationTest;
import com.microchip.lambda_auth.domain.Role;
import com.microchip.lambda_auth.domain.User;
import com.microchip.lambda_auth.domain.repo.UserRepository;
import com.microchip.lambda_auth.service.JwtService;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;

@AutoConfigureMockMvc
class UserControllerTest extends IntegrationTest {

    @Autowired MockMvc mvc;
    @Autowired UserRepository users;
    @Autowired JwtService jwtService;
    @Autowired PasswordEncoder encoder;

    @Test
    void adminListsUsers() throws Exception {
        User admin = user(Role.ADMIN);
        User other = user(Role.USER);

        mvc.perform(get("/api/users").header(HttpHeaders.AUTHORIZATION, bearer(admin)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[?(@.username == '%s')].role".formatted(other.getUsername())).value("USER"))
                .andExpect(jsonPath("$[0].passwordHash").doesNotExist());
    }

    @Test
    void disablingUserKillsLoginAndRefresh() throws Exception {
        String admin = bearer(user(Role.ADMIN));
        User target = user(Role.USER);
        String body = mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"%s\",\"password\":\"secret\"}".formatted(target.getUsername())))
                .andReturn().getResponse().getContentAsString();
        String refresh = "{\"refreshToken\":\"%s\"}".formatted(JsonPath.<String>read(body, "$.refreshToken"));

        mvc.perform(patch("/api/users/" + target.getId()).header(HttpHeaders.AUTHORIZATION, admin)
                        .contentType(MediaType.APPLICATION_JSON).content("{\"enabled\":false}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.enabled").value(false));

        mvc.perform(post("/api/auth/refresh").contentType(MediaType.APPLICATION_JSON).content(refresh))
                .andExpect(status().isUnauthorized());
        mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"%s\",\"password\":\"secret\"}".formatted(target.getUsername())))
                .andExpect(status().isUnauthorized());

        mvc.perform(patch("/api/users/" + target.getId()).header(HttpHeaders.AUTHORIZATION, admin)
                        .contentType(MediaType.APPLICATION_JSON).content("{\"enabled\":true}"))
                .andExpect(status().isOk());
        mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"%s\",\"password\":\"secret\"}".formatted(target.getUsername())))
                .andExpect(status().isOk());
    }

    @Test
    void adminCannotDisableSelf() throws Exception {
        User admin = user(Role.ADMIN);

        mvc.perform(patch("/api/users/" + admin.getId()).header(HttpHeaders.AUTHORIZATION, bearer(admin))
                        .contentType(MediaType.APPLICATION_JSON).content("{\"enabled\":false}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void unknownUserIs404() throws Exception {
        mvc.perform(patch("/api/users/" + UUID.randomUUID()).header(HttpHeaders.AUTHORIZATION, bearer(user(Role.ADMIN)))
                        .contentType(MediaType.APPLICATION_JSON).content("{\"enabled\":false}"))
                .andExpect(status().isNotFound());
    }

    @Test
    void regularUserIsForbidden() throws Exception {
        mvc.perform(get("/api/users").header(HttpHeaders.AUTHORIZATION, bearer(user(Role.USER))))
                .andExpect(status().isForbidden());
    }

    private String bearer(User user) {
        return "Bearer " + jwtService.issue(user);
    }

    private User user(Role role) {
        return users.save(new User("u" + UUID.randomUUID().toString().substring(0, 8), encoder.encode("secret"), role));
    }
}

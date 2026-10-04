package com.microchip.pathos_auth.web;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.jayway.jsonpath.JsonPath;
import com.microchip.pathos_auth.IntegrationTest;
import com.microchip.pathos_auth.domain.Role;
import com.microchip.pathos_auth.domain.User;
import com.microchip.pathos_auth.domain.repo.UserRepository;
import com.microchip.pathos_auth.service.JwtService;
import java.net.URI;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.util.UriComponentsBuilder;

@AutoConfigureMockMvc
class SignInWithPathosTest extends IntegrationTest {

    static final String FORUM = "http://forum.test/auth/pathos/callback";
    static final String VERIFIER = "pathos-test-verifier-0123456789-0123456789-0123456789";
    static final String CHALLENGE = challenge(VERIFIER);

    @Autowired MockMvc mvc;
    @Autowired UserRepository users;
    @Autowired PasswordEncoder encoder;
    @Autowired JwtService jwtService;
    @Autowired JwtDecoder decoder;

    @Test
    void allowedAccountComesBackWithACodeThatBuysTokens() throws Exception {
        User user = user(Role.USER, "forum");
        MockHttpSession session = signIn(user.getUsername(), "secret-pass");

        String back = authorize(session, "forum", FORUM);
        assertTrue(back.startsWith(FORUM + "?code="), back);
        assertEquals("st-1", query(back, "state"));

        String tokens = mvc.perform(post("/oauth2/token").with(httpBasic("forum", "forum-secret"))
                        .param("grant_type", "authorization_code").param("code", query(back, "code"))
                        .param("redirect_uri", FORUM).param("code_verifier", VERIFIER))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id_token").isNotEmpty())
                .andReturn().getResponse().getContentAsString();

        Jwt access = decoder.decode(JsonPath.read(tokens, "$.access_token"));
        assertEquals(user.getId().toString(), access.getSubject());
        assertEquals(user.getUsername(), access.getClaimAsString("username"));

        mvc.perform(get("/userinfo").header(HttpHeaders.AUTHORIZATION,
                        "Bearer " + JsonPath.<String>read(tokens, "$.access_token")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.sub").value(user.getId().toString()))
                .andExpect(jsonPath("$.preferred_username").value(user.getUsername()))
                .andExpect(jsonPath("$.role").value("USER"))
                .andExpect(jsonPath("$.access[0]").value("forum"));
    }

    @Test
    void accountThatWasNotLetInIsSentBackWithARefusal() throws Exception {
        MockHttpSession session = signIn(user(Role.USER).getUsername(), "secret-pass");

        String back = authorize(session, "forum", FORUM);

        assertTrue(back.startsWith(FORUM + "?error=access_denied"), back);
        assertEquals("st-1", query(back, "state"));
    }

    @Test
    void adminsAndOpenServicesNeedNoTick() throws Exception {
        assertNotNull(query(authorize(signIn(user(Role.ADMIN).getUsername(), "secret-pass"), "forum", FORUM), "code"));
        assertNotNull(query(authorize(signIn(user(Role.USER).getUsername(), "secret-pass"), "open",
                "http://open.test/cb"), "code"));
    }

    @Test
    void visitorWithoutASessionIsSentToTheSignInPage() throws Exception {
        MvcResult result = mvc.perform(authorizeRequest("forum", FORUM).accept(MediaType.TEXT_HTML))
                .andExpect(status().is3xxRedirection()).andReturn();
        assertTrue(result.getResponse().getRedirectedUrl().endsWith("/login"));

        String page = mvc.perform(get("/login")).andExpect(status().isOk()).andReturn().getResponse()
                .getContentAsString();
        assertTrue(page.contains("name=\"username\"") && page.contains("name=\"_csrf\""));
        assertTrue(!page.contains("<script"));
    }

    @Test
    void wrongPasswordAndThenTooManyOfThem() throws Exception {
        User user = user(Role.USER, "forum");
        for (int i = 0; i < 8; i++) {
            mvc.perform(post("/login").with(csrf()).param("username", user.getUsername()).param("password", "nope"))
                    .andExpect(status().is3xxRedirection())
                    .andExpect(r -> assertTrue(r.getResponse().getRedirectedUrl().endsWith("/login?error")));
        }
        // the right password no longer helps until the name has rested
        mvc.perform(post("/login").with(csrf()).param("username", user.getUsername()).param("password", "secret-pass"))
                .andExpect(r -> assertTrue(r.getResponse().getRedirectedUrl().endsWith("/login?error")));
    }

    @Test
    void foreignRedirectAndWrongSecretAreRefused() throws Exception {
        MockHttpSession session = signIn(user(Role.ADMIN).getUsername(), "secret-pass");

        mvc.perform(authorizeRequest("forum", "http://evil.test/cb").session(session))
                .andExpect(status().isBadRequest());

        String back = authorize(session, "forum", FORUM);
        mvc.perform(post("/oauth2/token").with(httpBasic("forum", "wrong"))
                        .param("grant_type", "authorization_code").param("code", query(back, "code"))
                        .param("redirect_uri", FORUM).param("code_verifier", VERIFIER))
                .andExpect(status().isUnauthorized());

        // a stolen code is useless without the verifier only the service holds
        mvc.perform(post("/oauth2/token").with(httpBasic("forum", "forum-secret"))
                        .param("grant_type", "authorization_code").param("code", query(back, "code"))
                        .param("redirect_uri", FORUM).param("code_verifier", "not-the-verifier-not-the-verifier-not-the-verifier"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void adminTicksAccessAndOnlyKnownServicesAreAccepted() throws Exception {
        String admin = "Bearer " + jwtService.issue(user(Role.ADMIN));
        User target = user(Role.USER);

        mvc.perform(get("/api/users/services").header(HttpHeaders.AUTHORIZATION, admin))
                .andExpect(jsonPath("$[0]").value("forum")).andExpect(jsonPath("$.length()").value(1));
        mvc.perform(patch("/api/users/" + target.getId()).header(HttpHeaders.AUTHORIZATION, admin)
                        .contentType(MediaType.APPLICATION_JSON).content("{\"access\":[\"forum\"]}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access[0]").value("forum"))
                .andExpect(jsonPath("$.enabled").value(true));
        mvc.perform(patch("/api/users/" + target.getId()).header(HttpHeaders.AUTHORIZATION, admin)
                        .contentType(MediaType.APPLICATION_JSON).content("{\"access\":[\"bank\"]}"))
                .andExpect(status().isBadRequest());

        assertNotNull(query(authorize(signIn(target.getUsername(), "secret-pass"), "forum", FORUM), "code"));

        mvc.perform(patch("/api/users/" + target.getId()).header(HttpHeaders.AUTHORIZATION, admin)
                        .contentType(MediaType.APPLICATION_JSON).content("{\"access\":[]}"))
                .andExpect(jsonPath("$.access.length()").value(0));
        assertTrue(authorize(signIn(target.getUsername(), "secret-pass"), "forum", FORUM).contains("error=access_denied"));
    }

    @Test
    void discoveryNamesTheEndpoints() throws Exception {
        mvc.perform(get("/.well-known/openid-configuration"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.authorization_endpoint").value("http://localhost:8081/oauth2/authorize"))
                .andExpect(jsonPath("$.userinfo_endpoint").value("http://localhost:8081/userinfo"));
        mvc.perform(get("/oauth2/jwks")).andExpect(status().isOk())
                .andExpect(jsonPath("$.keys[0].kid").value("pathos-auth-1"));
    }

    private MockHttpSession signIn(String username, String password) throws Exception {
        MockHttpSession session = new MockHttpSession();
        mvc.perform(post("/login").session(session).with(csrf()).param("username", username).param("password", password))
                .andExpect(status().is3xxRedirection())
                .andExpect(r -> assertTrue(!r.getResponse().getRedirectedUrl().contains("error"),
                        r.getResponse().getRedirectedUrl()));
        return (MockHttpSession) mvc.perform(get("/").session(session)).andReturn().getRequest().getSession(false);
    }

    private String authorize(MockHttpSession session, String client, String redirect) throws Exception {
        return mvc.perform(authorizeRequest(client, redirect).session(session))
                .andExpect(status().is3xxRedirection()).andReturn().getResponse().getRedirectedUrl();
    }

    private static org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder authorizeRequest(
            String client, String redirect) {
        return get("/oauth2/authorize").queryParam("response_type", "code").queryParam("client_id", client)
                .queryParam("redirect_uri", redirect).queryParam("scope", "openid profile").queryParam("state", "st-1")
                .queryParam("code_challenge", CHALLENGE).queryParam("code_challenge_method", "S256");
    }

    private static String challenge(String verifier) {
        try {
            byte[] digest = java.security.MessageDigest.getInstance("SHA-256")
                    .digest(verifier.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
            return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String query(String url, String name) {
        return UriComponentsBuilder.fromUri(URI.create(url)).build().getQueryParams().getFirst(name);
    }

    private User user(Role role, String... access) {
        User user = new User("u" + UUID.randomUUID().toString().substring(0, 8), encoder.encode("secret-pass"), role);
        user.setAccess(java.util.Set.of(access));
        return users.save(user);
    }
}

package com.microchip.pathos_auth.web;

import com.microchip.pathos_auth.domain.repo.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.UUID;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;

// The page a service sends a visitor to. Two fields and a button: no scripts, so nothing
// here can be turned against the password being typed.
@RestController
public class SignInController {

    private static final String PAGE = """
            <!doctype html>
            <html lang="%s">
            <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
            <meta name="color-scheme" content="light dark">
            <meta name="robots" content="noindex, nofollow">
            <title>pathos</title>
            <link rel="stylesheet" href="/auth.css">
            </head>
            <body>
            <main class="wrap">
              <a class="mark" href="https://pathos.su/">pathos</a>
              <div class="card">%s</div>
            </main>
            </body>
            </html>
            """;

    private static final String FORM = """
            <form class="stack" method="post" action="/login">
              <div class="lead"><b>%s</b></div>
              <input type="hidden" name="%s" value="%s">
              <label class="sr" for="u">%s</label>
              <input class="fld" id="u" name="username" type="text" autocomplete="username" autocapitalize="off" spellcheck="false" placeholder="%s" required autofocus>
              <label class="sr" for="p">%s</label>
              <input class="fld" id="p" name="password" type="password" autocomplete="current-password" placeholder="%s" required>
              %s
              <button class="btn" type="submit">%s</button>
            </form>
            """;

    private static final String SIGNED_IN = """
            <div class="lead"><b>%s</b></div>
            <form class="stack" method="post" action="/logout">
              <input type="hidden" name="%s" value="%s">
              <button class="btn ghost" type="submit">%s</button>
            </form>
            """;

    private final UserRepository users;

    public SignInController(UserRepository users) {
        this.users = users;
    }

    @GetMapping(value = "/login", produces = MediaType.TEXT_HTML_VALUE)
    public String signIn(HttpServletRequest request, CsrfToken csrf,
            @RequestParam(required = false) String error, @RequestParam(required = false) String out) {
        boolean ru = russian(request);
        String note = error != null ? note(ru ? "неверное имя или пароль" : "wrong username or password", true)
                : out != null ? note(ru ? "вы вышли" : "signed out", false) : "";
        return PAGE.formatted(ru ? "ru" : "en", FORM.formatted(
                ru ? "вход в pathos" : "sign in to pathos",
                HtmlUtils.htmlEscape(csrf.getParameterName()), HtmlUtils.htmlEscape(csrf.getToken()),
                ru ? "имя" : "username", ru ? "имя" : "username",
                ru ? "пароль" : "password", ru ? "пароль" : "password",
                note, ru ? "войти" : "sign in"));
    }

    @GetMapping(value = "/", produces = MediaType.TEXT_HTML_VALUE)
    public String home(HttpServletRequest request, CsrfToken csrf, Authentication authentication) {
        boolean ru = russian(request);
        String name = name(authentication);
        if (name == null) {
            return signIn(request, csrf, null, null);
        }
        return PAGE.formatted(ru ? "ru" : "en", SIGNED_IN.formatted(
                HtmlUtils.htmlEscape(name, StandardCharsets.UTF_8.name()),
                HtmlUtils.htmlEscape(csrf.getParameterName()), HtmlUtils.htmlEscape(csrf.getToken()),
                ru ? "выйти" : "sign out"));
    }

    private String name(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return null;
        }
        try {
            return users.findById(UUID.fromString(authentication.getName())).map(u -> u.getUsername()).orElse(null);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private static String note(String text, boolean bad) {
        return "<span class=\"" + (bad ? "err-line" : "hint") + "\">" + text + "</span>";
    }

    private static boolean russian(HttpServletRequest request) {
        String accept = request.getHeader("Accept-Language");
        return accept == null || accept.toLowerCase(Locale.ROOT).matches("^(ru|uk|be|kk)\\b.*");
    }
}

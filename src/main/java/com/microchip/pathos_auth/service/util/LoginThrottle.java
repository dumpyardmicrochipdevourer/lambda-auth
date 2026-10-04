package com.microchip.pathos_auth.service.util;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;

// The sign-in page is reachable from the internet without a gateway in front of it,
// so guessing a password is slowed down here: a few misses and the name rests for a while.
@Component
public class LoginThrottle {

    private static final int MAX_FAILURES = 8;
    private static final Duration WINDOW = Duration.ofMinutes(15);

    private final Map<String, Deque<Instant>> failures = new ConcurrentHashMap<>();

    public boolean blocked(String username) {
        Deque<Instant> times = failures.get(key(username));
        if (times == null) {
            return false;
        }
        synchronized (times) {
            prune(times);
            return times.size() >= MAX_FAILURES;
        }
    }

    public void failed(String username) {
        failures.values().removeIf(q -> { synchronized (q) { prune(q); return q.isEmpty(); } });
        Deque<Instant> times = failures.computeIfAbsent(key(username), k -> new ArrayDeque<>());
        synchronized (times) {
            times.addLast(Instant.now());
        }
    }

    public void succeeded(String username) {
        failures.remove(key(username));
    }

    private static void prune(Deque<Instant> times) {
        Instant edge = Instant.now().minus(WINDOW);
        while (!times.isEmpty() && times.peekFirst().isBefore(edge)) {
            times.pollFirst();
        }
    }

    private static String key(String username) {
        return username == null ? "" : username.strip().toLowerCase(Locale.ROOT);
    }
}

package com.microchip.pathos_auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class PathosAuthApplication {

    public static void main(String[] args) {
        SpringApplication.run(PathosAuthApplication.class, args);
    }
}

package com.microchip.lambda_auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class LambdaAuthApplication {

    public static void main(String[] args) {
        SpringApplication.run(LambdaAuthApplication.class, args);
    }
}

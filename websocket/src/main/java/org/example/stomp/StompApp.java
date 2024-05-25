package org.example.stomp;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;

/**
 * @author infosec
 * @since 2024/3/25
 */
//@SpringBootApplication
public class StompApp {

    public static void main(String[] args) {
        SpringApplication.run(StompApp.class, args);
    }

    @Bean
    public CommandLineRunner commandLineRunner(ApplicationContext ctx) {
        return args -> {

            System.out.println("application started");

        };
    }

}

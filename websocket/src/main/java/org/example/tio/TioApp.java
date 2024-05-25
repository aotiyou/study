package org.example.tio;


import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.tio.websocket.starter.EnableTioWebSocketServer;

@SpringBootApplication
@EnableTioWebSocketServer
public class TioApp {

    public static void main(String[] args) {
        SpringApplication.run(TioApp.class, args);
    }

    @Bean
    public CommandLineRunner commandLineRunner(ApplicationContext ctx) {
        return args -> {
            System.out.println("application started");
        };
    }
}



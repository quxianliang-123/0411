package com.example.swagger;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.web.client.RestTemplate;

import com.example.swagger.controller.KeycloakClient;


@SpringBootApplication
@ComponentScan("com.example.swagger.controller")
public class KeycloakRun {

	public static void main(String[] args) {
		SpringApplication.run(KeycloakRun.class, args);
	}
	

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
    
    @Bean
    public KeycloakClient keycloakClient() {
        return new KeycloakClient();
    }
}

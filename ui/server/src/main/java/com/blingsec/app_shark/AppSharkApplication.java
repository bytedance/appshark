package com.blingsec.app_shark;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@ComponentScan(basePackages = {"com.blingsec"})
@EnableScheduling
public class AppSharkApplication {

    public static void main(String[] args) {
            SpringApplication.run(AppSharkApplication.class, args);

    }

}

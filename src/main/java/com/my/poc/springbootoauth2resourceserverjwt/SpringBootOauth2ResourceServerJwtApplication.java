package com.my.poc.springbootoauth2resourceserverjwt;

import com.my.poc.springbootoauth2resourceserverjwt.security.CustomTokenProvider;
import com.my.poc.springbootoauth2resourceserverjwt.security.TokenProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class SpringBootOauth2ResourceServerJwtApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringBootOauth2ResourceServerJwtApplication.class, args);
	}

	@Bean
	TokenProvider tokenProvider() {
		return new CustomTokenProvider();
	}
}

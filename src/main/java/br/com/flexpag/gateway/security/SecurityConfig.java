package br.com.flexpag.gateway.security;

import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import reactor.core.publisher.Mono;

@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    SecurityWebFilterChain springWebFilterChain(ServerHttpSecurity http) {
        String[] patterns = new String[] {"/auth/**"};

        return http
                .cors().disable()
                .csrf().disable()
                .exceptionHandling()
                .authenticationEntryPoint((swe, e) -> Mono.fromRunnable(() ->
                    swe.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED)
                )).accessDeniedHandler((swe, e) -> Mono.fromRunnable(() ->
                    swe.getResponse().setStatusCode(HttpStatus.FORBIDDEN)
                )).and()
                .authorizeExchange()
                .pathMatchers(patterns).permitAll()
                .pathMatchers(HttpMethod.OPTIONS).permitAll()
                .anyExchange().permitAll()
                .and()
                .build();
    }
}

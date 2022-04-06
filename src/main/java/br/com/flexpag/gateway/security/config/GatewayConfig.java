package br.com.flexpag.gateway.security.config;

import br.com.flexpag.gateway.security.filter.AuthorizationFilter;
import lombok.AllArgsConstructor;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@AllArgsConstructor
public class GatewayConfig {

    private final AuthorizationFilter authFilter;

    @Bean
    public RouteLocator routes(RouteLocatorBuilder builder) {
        return builder.routes()
                .route("auth-ms", r -> r.path("/auth/**")
                        .filters(f -> f.filter(authFilter))
                        .uri("lb://auth-ms"))
                .build();
    }
}

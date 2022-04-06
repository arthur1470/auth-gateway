package br.com.flexpag.gateway.security.filter;

import br.com.flexpag.gateway.util.JWTUtils;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.AllArgsConstructor;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Optional;

@Component
@RefreshScope
@AllArgsConstructor
public class AuthorizationFilter implements GatewayFilter {

    private final JWTUtils jwtUtils;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();

        this.validateRequiredHeaders(request, exchange);

        if (RouterValidator.isSecured.test(request)) {
            var jwtToken = jwtUtils.getDecodedJWTFromRequest(request);

            this.validateAuthMissing(request, exchange);
            this.validateTokenAndHeaderInformationMatches(request, exchange, jwtToken);
            this.populateRequestWithHeaders(request, jwtToken);
        }

        return chain.filter(exchange);
    }

    private void validateRequiredHeaders(ServerHttpRequest request, ServerWebExchange exchange) {
        if(getApplicationHeader(request).isBlank())
            this.onError(exchange, "Application header is missing in request", HttpStatus.UNAUTHORIZED);

        if(getOrganizationHeader(request).isBlank())
            this.onError(exchange, "Organization header is missing in request", HttpStatus.UNAUTHORIZED);
    }

    private void validateAuthMissing(ServerHttpRequest request, ServerWebExchange exchange) {
        if(!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION))
            this.onError(exchange, "Authorization header is missing in request", HttpStatus.UNAUTHORIZED);
    }

    private void populateRequestWithHeaders(ServerHttpRequest request, DecodedJWT decodedJWT) {
        request.mutate()
                .header("userId", String.valueOf(decodedJWT.getSubject()))
                .header("roles", String.valueOf(decodedJWT.getClaim("roles")))
                .header("permissions", String.valueOf(decodedJWT.getClaim("permissions")))
                .build();
    }

    private void validateTokenAndHeaderInformationMatches(ServerHttpRequest request, ServerWebExchange exchange, DecodedJWT jwtToken) {
        var tokenOrganization = getTokenOrganizationId(jwtToken);
        var tokenApplication = getTokenApplicationId(jwtToken);

        var headerOrganization = getOrganizationHeader(request);
        var headerApplication = getApplicationHeader(request);

        if(!tokenOrganization.equals(headerOrganization))
            this.onError(exchange, "Incorrect organization header for authorization token.", HttpStatus.UNAUTHORIZED);

        if(!tokenApplication.equals(headerApplication))
            this.onError(exchange, "Incorrect application header for authorization token.", HttpStatus.UNAUTHORIZED);
    }

    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);

        return response.setComplete();
    }

    private String getApplicationHeader(ServerHttpRequest request) {
        return Optional.of(request.getHeaders().getOrEmpty("applicationId"))
                .orElse(List.of(""))
                .get(0);
    }

    private String getOrganizationHeader(ServerHttpRequest request) {
        return Optional.of(request.getHeaders().getOrEmpty("organizationId"))
                .orElse(List.of(""))
                .get(0);
    }

    private String getTokenOrganizationId(DecodedJWT decodedJWT) {
        return decodedJWT.getClaim("organization").asString();
    }

    private String getTokenApplicationId(DecodedJWT decodedJWT) {
        return decodedJWT.getClaim("application").asString();
    }
}

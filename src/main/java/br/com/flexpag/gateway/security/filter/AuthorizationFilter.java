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

@Component
@RefreshScope
@AllArgsConstructor
public class AuthorizationFilter implements GatewayFilter {

    private final RouterValidator routerValidator;
    private final JWTUtils jwtUtils;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        var organizationId = request.getHeaders().get("organizationId");
        var applicationId = request.getHeaders().get("applicationId");

        if (routerValidator.isSecured.test(request)) {
            if (this.isAuthMissing(request))
                return this.onError(exchange, "Authorization header is missing in request", HttpStatus.UNAUTHORIZED);

            final String token = this.getAuthHeader(request);


            this.populateRequestWithHeaders(exchange, token);
        }

        return chain.filter(exchange);
    }

    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);
        return response.setComplete();
    }

    private String getAuthHeader(ServerHttpRequest request) {
        return request.getHeaders().getOrEmpty(HttpHeaders.AUTHORIZATION).get(0);
    }

    private boolean isAuthMissing(ServerHttpRequest request) {
        return !request.getHeaders().containsKey("Authorization");
    }

    private void populateRequestWithHeaders(ServerWebExchange exchange,  String token) {
        DecodedJWT decodedJWT = jwtUtils.getDecodedJWTFromRequest(exchange.getRequest());

        exchange.getRequest().mutate()
                .header("userId", String.valueOf(decodedJWT.getSubject()))
                .header("roles", String.valueOf(decodedJWT.getClaim("roles")))
                .build();
    }


//	private final JWTUtils jwtUtils;
//
//	@Override
//	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
//		var authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
//		boolean hasAuthorizationHeader = !ObjectUtils.isEmpty(authorizationHeader) && authorizationHeader.startsWith("Bearer ");
//
//		var organizationId = request.getHeader("organizationId");
//		var applicationId = request.getHeader("applicationId");
//
//		if(request.getServletPath().equals("/login") || !hasAuthorizationHeader) {
//			filterChain.doFilter(request, response);
//			return;
//		}
//
//		DecodedJWT decodedJWT = jwtUtils.getDecodedJWTFromRequest(request);
//
//		String userId = decodedJWT.getSubject();
//		String[] roles = decodedJWT.getClaim("roles").asArray(String.class);
////		String[] permissions = decodedJWT.getClaim("permissions").asArray(String.class);
//
//		List<SimpleGrantedAuthority> authorities = new ArrayList<>();
//		Arrays.stream(roles).forEach(role -> authorities.add(new SimpleGrantedAuthority(role)));
//
//		SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(userId, null, authorities));
//
//		filterChain.doFilter(request, response);
//	}
}

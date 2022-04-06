package br.com.flexpag.gateway.util;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.ObjectUtils;

@Component
public final class JWTUtils {

	private final Algorithm algorithm;

	public JWTUtils(@Value("${TOKEN.PASSWORD}") String tokenPassword) {
		System.out.println(tokenPassword);
		this.algorithm = Algorithm.HMAC256(tokenPassword);
	}

	public String getTokenSubject(ServerHttpRequest request) {
		var token = getTokenFromRequest(request);
		return getDecodedJWT(token).getSubject();
	}

	public String getTokenFromRequest(ServerHttpRequest request) {

		String authorizationHeader = request.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);

		if (ObjectUtils.isEmpty(authorizationHeader) || !authorizationHeader.startsWith("Bearer "))
			throw new RuntimeException("Refresh token is missing");

		return authorizationHeader.substring("Bearer ".length());
	}

	public DecodedJWT getDecodedJWT(String token) {
		JWTVerifier verifier = JWT.require(algorithm).build();
		return verifier.verify(token);
	}

	public DecodedJWT getDecodedJWTFromRequest(ServerHttpRequest request) {
		var token = getTokenFromRequest(request);
		return getDecodedJWT(token);
	}
}

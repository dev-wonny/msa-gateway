package com.sparta.msa_exam.gateway;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

@Slf4j
@Component
public class LocalJwtAuthenticationFilter implements GlobalFilter {

	@Value("${service.jwt.secret-key}")
	private String secretKey;

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
		final String path = exchange.getRequest().getURI().getPath();
		if (path.equals("/auth/signIn") || path.equals("/auth/signUp")) {
			/*
			if (!validateUserId(exchange)) {
				exchange.getResponse().setStatusCode(HttpStatus.BAD_REQUEST);
				return exchange.getResponse().setComplete();//응답 본문을 작성할 필요가 없고, 단순히 상태 코드만 설정하여 응답을 종료
			}
			 */
			return chain.filter(exchange);  // /auth 경로는 필터를 적용하지 않음
		}

		final Optional<String> tokenOpt = extractToken(exchange);

		if (tokenOpt.isEmpty() || !validateToken(tokenOpt, exchange)) {
			exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
			return exchange.getResponse().setComplete();
		}

		return chain.filter(exchange);
	}

	private Optional<String> extractToken(ServerWebExchange exchange) {
		final String authHeader = exchange.getRequest().getHeaders().getFirst("Authorization");
		if (authHeader != null && authHeader.startsWith("Bearer ")) {
			return Optional.of(authHeader.substring(7));
		}
		return Optional.empty();
	}

	private boolean validateUserId(ServerWebExchange exchange) {
		String userId = exchange.getRequest().getQueryParams().getFirst("userId");
		log.debug("userId={}", userId);
		return userId != null && !userId.isEmpty();
	}

	private boolean validateToken(Optional<String> tokenOpt, ServerWebExchange exchange) {
		if (tokenOpt.isPresent()) {
			try {
				final SecretKey key = Keys.hmacShaKeyFor(Decoders.BASE64URL.decode(secretKey));
				Jws<Claims> claimsJws = Jwts.parser()
						.verifyWith(key)
						.build().parseSignedClaims(tokenOpt.get());
				log.info("#####payload :: " + claimsJws.getPayload().toString());

				Claims claims = claimsJws.getBody();
				// gateway에서 다른 서비스로 헤더로 데이터 보냄
				exchange.getRequest().mutate()
						.header("X-User-Id", claims.get("user_id").toString())
						.header("X-Role", claims.get("role").toString())
						.build();
				// 추가적인 검증 로직 (예: 토큰 만료 여부 확인 등)을 여기에 추가할 수 있습니다.

				return true;
			} catch (Exception e) {
				log.error("Token validation failed", e);
				return false;
			}
		}
		log.warn("Token is missing");
		return false;
	}


}
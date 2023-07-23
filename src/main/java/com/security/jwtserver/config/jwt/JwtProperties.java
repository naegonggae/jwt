package com.security.jwtserver.config.jwt;

public interface JwtProperties {
	String SECRET = "cos"; // 우리 서버만 알고 있는 비밀값
	int EXPIRATION_TIME = 60000 * 30; // 10일 (1/1000초) // (60000 * 10) -> 60000 =1분
	String TOKEN_PREFIX = "Bearer ";
	String HEADER_STRING = "Authorization";
}

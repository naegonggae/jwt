package com.security.jwtserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

// cors 설정을 필터를 하나 만들어서 해줬다.
@Configuration
public class CorsConfig {

	@Bean
	public CorsFilter corsFilter() {
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		CorsConfiguration config = new CorsConfiguration();
		config.setAllowCredentials(true); // 내 서버가 응답을 할때 json 을 자바스크립트에서 처리할 수 있게 할지를 설정하는 것
		config.addAllowedOrigin("*"); // 모든 ip 응답을 허용하겠다
		config.addAllowedHeader("*"); // 모든 헤더 응답을 허용하겠다.
		config.addAllowedMethod("*"); // 모든 get, poet, put, delete, patch 요청을 허용하겠다.

		source.registerCorsConfiguration("/api/**", config);
		return new CorsFilter(source);
	}

}

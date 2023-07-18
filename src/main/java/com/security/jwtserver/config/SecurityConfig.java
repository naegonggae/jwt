package com.security.jwtserver.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

	private final CorsFilter corsFilter;

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
		httpSecurity
				.csrf().disable()
				.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // 세션을 사용하지 않겠다.
				.and()
				// 모든 요청은 아래 필터를 탐
				// @CrossOrigin(인증X), 시큐리티 필터에 등록인증(O)
				// 근데 이렇게 하면 시큐리티를 사용하고 있지만 모든페이지에 접근이 가능하게 됨
				.addFilter(corsFilter) // 내 서버는 cors 정책에서 벗어날수 있음 // crossOrigin 요청이와도 다 허용됨
				.formLogin().disable() // jwt 기반이니까 form 로그인 사용안함
				.httpBasic().disable() // 기본적인 로그인방식을 사용하지 않음
				.authorizeHttpRequests()
				.requestMatchers("/api/v1/user**")
				.hasAnyRole("USER", "ADMIN", "MANAGER")
				.requestMatchers("/api/v1/admin**")
				.hasRole("ADMIN")
				.requestMatchers("/api/v1/manager**")
				.hasAnyRole("ADMIN", "MANAGER")
				.anyRequest().permitAll();

		return httpSecurity.build();
	}

}

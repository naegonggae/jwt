package com.security.jwtserver.config;

import com.security.jwtserver.config.jwt.JwtAuthenticationFilter;
import com.security.jwtserver.filter.MyFilter1;
import com.security.jwtserver.filter.MyFilter3;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

	private final CorsFilter corsFilter;
	private final CorsConfig corsConfig;

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
		httpSecurity
				.addFilterBefore(new MyFilter3(), SecurityContextHolderFilter.class) // 이렇게하면 시큐리티 필터보다 엄청 먼저 실행됨
				// 근데 궅이 시큐리티 필터에 걸필요는 없고 다른곳에 걸거같음 - 확인만 함
				// 달면 오류남 MyFilter 는 시큐리티필터가 아니고 그냥 필터라서 시큐리티 체인에 들어가지못함그래서 시큐리티 체인이 시작되기전이나 후에 넣어라 해서 조치해줌
				.csrf().disable()
				.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // 세션을 사용하지 않겠다.
				.and()
				// 모든 요청은 아래 필터를 탐
				// @CrossOrigin(인증X), 시큐리티 필터에 등록인증(O)
				// 근데 이렇게 하면 시큐리티를 사용하고 있지만 모든페이지에 접근이 가능하게 됨
				.addFilter(corsFilter) // 내 서버는 cors 정책에서 벗어날수 있음 // crossOrigin 요청이와도 다 허용됨
				.formLogin().disable() // jwt 기반이니까 form 태크 만들어서 로그인하는거 안한다는 의미
				.httpBasic().disable() // 기본적인 로그인방식을 사용하지 않음
				.apply(new MyCustomDsl()) // authenticationManager 파라미터를 던져줘야함
				.and()
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

	public class MyCustomDsl extends AbstractHttpConfigurer<MyCustomDsl, HttpSecurity> {
		@Override
		public void configure(HttpSecurity http) throws Exception {
			AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
			http
					.addFilter(corsConfig.corsFilter())
					.addFilter(new JwtAuthenticationFilter(authenticationManager));
					//.addFilter(new JwtAuthorizationFilter(authenticationManager, userRepository));
		}
	}
}

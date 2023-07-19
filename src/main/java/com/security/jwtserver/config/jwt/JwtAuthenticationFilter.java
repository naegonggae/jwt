package com.security.jwtserver.config.jwt;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

// 스프링 시큐리티에 UsernamePasswordAuthenticationFilter 가 있음, 근데 FormLogin 을 사용안하기 때문에 스프링 시큐리티 필터에서 제외되어있는 상테
// 그래서 UsernamePasswordAuthenticationFilter 를 추가시켜줘야함
// 로그인 요청해서 id, password 전송하면(post)
// UsernamePasswordAuthenticationFilter 작동함
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
	private final AuthenticationManager authenticationManager;

	// 로그인요청을 하면 로그인 시도를 위해서 실행되는 함수
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request,
			HttpServletResponse response) throws AuthenticationException {
		System.out.println("JwtAuthenticationFilter: 로그인 시도중");

		//1. username, password 받아서

		//2. 정상인지 로그인시도를 해보는거에요.
		//authenticationManager 로 로그인시도를 하면 PrincipalDetailsService 가 호출이 됨 ->  loadUserByUsername 호출

		//3. PrincipalDetails 를 세션에 담고 // 권한관리해주려고

		//4. jwt token 을 만들어서 응답해주면됨
		return super.attemptAuthentication(request, response);
	}
}

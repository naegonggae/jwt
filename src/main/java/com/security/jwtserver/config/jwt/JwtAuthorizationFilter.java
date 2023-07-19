package com.security.jwtserver.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.security.jwtserver.config.auth.PrincipalDetails;
import com.security.jwtserver.model.User;
import com.security.jwtserver.repository.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

// 시큐리티가 필터를 가지고 있는데 그 필터중에 BasicAuthenticationFilter 라는 것이 있음
// 권한이나 인증이 필요한 특정 주소를 요청했을때 위 주소가 무조건 타게 되어있음
// 만약에 권한이나 인증이 필요한 주소가 아니라면 이 필터 안타요
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

	private UserRepository userRepository;
	public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
		super(authenticationManager);
		this.userRepository = userRepository;
	}

	// 인증이나 권한이 필요한 주소 요청이 있을때 해당 필터를 타게 될것
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
			FilterChain chain) throws IOException, ServletException {
		//super.doFilterInternal(request, response, chain); 이걸 살려두면 응답이 두번되서 오류가 남
		System.out.println("인증이나 권한이 필요한 주소가 요청됨");

		System.out.println("1===");
		String jwtHeader = request.getHeader("Authorization");
		System.out.println("jwtHeader = " + jwtHeader);
		System.out.println("2===");

		//header 가 있는지 확인
		if (jwtHeader == null || !jwtHeader.startsWith("Bearer")) {
			System.out.println("중단됨");

			chain.doFilter(request, response);
			return;
		}

		//JWT 토큰을 검증해서 정상적인 사용자인지 확인
		String jwtToken = request.getHeader("Authorization").replace("Bearer ", "");
		// 서명이 정상적으로 되서 username 을 들고옴
		// 서명이 잘 됐다 = username 을 잘 들고왔다.
		String username = JWT.require(Algorithm.HMAC512("cos"))
				.build().verify(jwtToken).getClaim("username").asString();

		// 서명이 정상적으로됨
		if (username != null) {
			System.out.println("username 정상");
			User userEntity = userRepository.findByUsername(username);
			System.out.println("userEntity.getUsername() = " + userEntity.getUsername());

			// Authentication 객체 강제로 만들기 -> username 이 null 이 아니기 때문에 정상적으로 만들수있음
			// jwt 토큰 서명을 통해서 서명이 정상이면 authentication 객체가 만들어준다.
			PrincipalDetails principalDetails = new PrincipalDetails(userEntity);
			Authentication authentication = new UsernamePasswordAuthenticationToken(
					principalDetails, null, principalDetails.getAuthorities()); // 비밀번호는 딱히 필요없어서 null 처리

			// 강제로 시큐리티 세션에 접근해서 authentication 객체를 저장
			SecurityContextHolder.getContext().setAuthentication(authentication);

		}
		chain.doFilter(request, response);

	}

	public JwtAuthorizationFilter(AuthenticationManager authenticationManager,
			AuthenticationEntryPoint authenticationEntryPoint) {
		super(authenticationManager, authenticationEntryPoint);
	}
}

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

		System.out.println("JwtAuthorizationFilter : 인증이나 권한이 필요한 주소가 요청됨");

		// header 에 Authorization 항목 가져오기
		String jwtHeader = request.getHeader(JwtProperties.HEADER_STRING); // "Authorization"
		System.out.println("JwtAuthorizationFilter - jwtHeader = " + jwtHeader);

		//header 가 있는지 확인
		if (jwtHeader == null || !jwtHeader.startsWith(JwtProperties.TOKEN_PREFIX)) {
			System.out.println("JwtAuthorizationFilter : 헤더가 없거나 형식이 잘못되어 중단");

			chain.doFilter(request, response);
			return;
		}

		//JWT 토큰을 검증해서 정상적인 사용자인지 확인

		// 헤더 형식 제외하고 생 토큰만 추출
		String jwtToken = request.getHeader(JwtProperties.HEADER_STRING).replace(JwtProperties.TOKEN_PREFIX, "");

		// 서명이 정상적으로 되서 username 을 들고옴
		// 서명이 잘 됐다 = username 을 잘 들고왔다.
		// 서명이 됐다는 의미는 여기서는 대칭키만 사용하기 때문에 토큰을 복호화해서 정보에 접근할 수 있다면 무결성도 지켜졌고 서명도 잘됐다고 한다.
		// 복호화를 하고 username 도 DB 에 있는지 확인하고 토큰 유효기간등도 추가로 확인을 해야한다.


		System.out.println("생 jwtToken = " + jwtToken);

		// 토큰 검증 (이게 인증이기 때문에 AuthenticationManager 도 필요 없음)
		// 내가 SecurityContext 에 집적접근해서 세션을 만들때 자동으로 UserDetailsService 에 있는
		// loadByUsername 이 호출됨.

		// 클레임(Claims)이란?
		//- 페이로드 구성에 담을 key 와 value 의 한쌍으로 이루어 진 형태를 클레임이라고 합니다.
		//- 위에 예시로는 "sub": "1234567890"가 하나의 클레임입니다.

		// secret 키를 통해서 username claim 에 접근한다.
		String username = JWT.require(Algorithm.HMAC512(JwtProperties.SECRET))
				.build().verify(jwtToken).getClaim("username").asString();

		System.out.println("username = " + username); // 이게 DB 정보와 같다면 무결성 검증이 잘된것임
		System.out.println("JwtAuthorizationFilter : 정상적인 형식의 토큰을 전달받음");

		// 서명이 정상적으로됨
		if (username != null) {
			System.out.println("JwtAuthorizationFilter username 정상");
			User userEntity = userRepository.findByUsername(username);
			System.out.println("userEntity = " + userEntity);
			// 인증은 토큰 검증시 끝. 인증을 하기 위해서가 아닌 스프링 시큐리티가 수행해주는 권한 처리를 위해
			// 아래와 같이 토큰을 만들어서 Authentication 객체를 강제로 만들고 그걸 세션에 저장!

			// Authentication 객체 강제로 만들기 -> username 이 null 이 아니기 때문에 정상적으로 만들수있음
			// jwt 토큰 서명을 통해서 서명이 정상이면 authentication 객체가 만들어준다.
			PrincipalDetails principalDetails = new PrincipalDetails(userEntity);
			Authentication authentication = new UsernamePasswordAuthenticationToken(
					principalDetails, null, principalDetails.getAuthorities()); // 비밀번호는 딱히 필요없어서 null 처리
			// 패스워드는 모르니까 null 처리, 어차피 지금 인증하는게 아니니까!! 비밀성 유지를 위해서라도 비밀번호는 Null 로 해야한다.
			// 그리고 패스워드는 검증하는데 굳이 필요하지 않다. 보통 식별 ID 나 username 등으로 검증한다.

			// 강제로 시큐리티 세션에 접근해서 authentication 객체를 저장
			// 세션이 유지 될동안 저장이된다. 저장되어있는 동안에는 인가를 검증할때마다 활용된다.
			SecurityContextHolder.getContext().setAuthentication(authentication);

		}
		chain.doFilter(request, response); // 다음 필터로 이동

	}

//	public JwtAuthorizationFilter(AuthenticationManager authenticationManager,
//			AuthenticationEntryPoint authenticationEntryPoint) {
//		super(authenticationManager, authenticationEntryPoint);
//	}
}

//JWT 유효성 검사 과정
//
//사용자가 요청에 JWT 를 보내면 서버에서 시크릿키 만을 이용해서 JWT의 토큰의 유효성을 체크합니다. (Signature)
//유효한 토큰이라면 사용자 인증을 거칩니다. (Payload)
//그 다음, 토큰의 만료기간을 체크하고
//권한을 체크합니다.
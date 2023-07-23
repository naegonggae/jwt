package com.security.jwtserver.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.jwtserver.config.auth.PrincipalDetails;
import com.security.jwtserver.dto.LoginRequestDto;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

// 스프링 시큐리티에 UsernamePasswordAuthenticationFilter 가 있음, 근데 FormLogin 을 사용안하기 때문에 스프링 시큐리티 필터에서 제외되어있는 상테
// 그래서 UsernamePasswordAuthenticationFilter 를 추가시켜줘야함
// 로그인 요청해서 id, password 전송하면(post)
// UsernamePasswordAuthenticationFilter 작동함
// UsernamePasswordAuthenticationFilter 를 커스텀 한거야? ㅇㅇ 밑에 보니까 상속도 받았네
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

	// Authentication 객체 만들어서 리턴 => 의존 : AuthenticationManager
	// 인증 요청시에 실행되는 함수 => /login
	private final AuthenticationManager authenticationManager;

	// 로그인 요청을 했을 때 인증역할
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request,
			HttpServletResponse response) throws AuthenticationException {

		System.out.println("JwtAuthenticationFilter : 로그인 시도중");

		// 1. 유저의 request 에 있는 username 과 password 를 파싱해서 자바 Object 로 받기
		ObjectMapper om = new ObjectMapper();
		LoginRequestDto loginRequestDto = null;
		try {
			loginRequestDto = om.readValue(request.getInputStream(), LoginRequestDto.class);
		} catch (Exception e) {
			e.printStackTrace();
		}

		System.out.println("JwtAuthenticationFilter : " + loginRequestDto);

		// 2. username, password 토큰 생성
		UsernamePasswordAuthenticationToken authenticationToken =
				new UsernamePasswordAuthenticationToken(loginRequestDto.getUsername(), loginRequestDto.getPassword());

		System.out.println("JwtAuthenticationFilter : 토큰생성완료");

		// 3. authenticationManager 에 토큰을 넣어서 던지면 인증을 해줌 -> 인증을 하면 authentication 받음
		// authenticationManager 로 로그인시도를 하면 PrincipalDetailsService 가 호출이 됨 ->  loadUserByUsername 호출
		System.out.println("JwtAuthenticationFilter : authenticationManager 에게 토큰 넘김");
		Authentication authentication = authenticationManager.authenticate(authenticationToken);

		// 4. 내가 입력한 username 과 password 가 SecurityContext 에서 꺼내지면 로그인이 정상적으로 되었다는 뜻
		// 왜? SecurityContext 에 저장되려면 authenticationManager 가 인증을 끝낸것을 의미
		PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();

		System.out.println("JwtAuthenticationFilter : 로그인 완료됨");
		System.out.println("JwtAuthenticationFilter - principalDetails = " + principalDetails);
		System.out.println("=====================");

		// 이제 jwt 토큰을 만드는데 여기에 만들필요가 없음 왜냐? -> attemptAuthentication 가 종료되고 그 뒤에 실행되는 함수가 있음
		// 그 함수는 바로 successfulAuthentication 임

		// authentication 객체를 session 영역에 저장을 해야하고 그 방법은 return 해주면 끝임
		// 이유 = 권한 관리를 시큐리티가 대신해주기때문에 편하려고 하는거임
		// 목적 = 굳이 jwt 토큰을 사용하면서 세션을 만들이유가 없는데, 단지 권한 처리때문에 세션에 넣어줍니다.

		return authentication; // authentication 객체가 세션에 저장됨

	}

	// attemptAuthentication 실행 후 정상적으로 인증이 되면 successfulAuthentication 함수가 실행이 됨
	// Jwt 토큰을 만들어서 request 요청한 사용자에게 jwt 토큰을 response 해주면됨
	// 여기서 context 에 유저 검증 정보가 저장된다. 세션에도 저장됨
	@Override
	protected void successfulAuthentication(HttpServletRequest request,
			HttpServletResponse response, FilterChain chain, Authentication authResult)
			throws IOException, ServletException {

		System.out.println("successfulAuthentication 이 실행됨, 인증이 완료되었음");

		PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

		// jwt 토큰 만들기 - 빌더패턴
		// RSA 방식(공개키 개인키 방식)은 아니고 Hash 방식(secret 키를 갖는 방식)
		String jwtToken = JWT.create()
				.withSubject(principalDetails.getUsername())
				.withExpiresAt(new Date(System.currentTimeMillis()+JwtProperties.EXPIRATION_TIME)) // 만료시간
				.withClaim("id", principalDetails.getUser().getId())
				.withClaim("username", principalDetails.getUser().getUsername())
				.sign(Algorithm.HMAC512(JwtProperties.SECRET)); // SECRET = 사이트만 알고있는 고유값

		System.out.println("successfulAuthentication - jwtToken = " + jwtToken);

		// 응답 헤더에 토큰을 담아서 사용자에게 리턴한다. -> 앞으로 로그인시 사용
		response.addHeader(JwtProperties.HEADER_STRING, JwtProperties.TOKEN_PREFIX + jwtToken);
		// 여기까지 로그인도하고 JWT 토큰도 만들어줬다.
		// 이제 로그인한상태에서 서버에 개인정보를 요청하면 서버에서 JWT 토큰이 유효한지 판단을 해서 요청을 받을지말지 결정한다.

		System.out.println("=====================");
	}

}

// 1. 유저가 로그인한 정보인 아이디와 비밀번호를 추출한다.

// 2. 추출한 아이디와 비밀번호로 토큰을 만든다.

// 3. AuthenticationManager 에 토큰을 넣어서 던지면 인증을 해줌 -> 인증을 하면 authentication 받음
// 3-1. PrincipalDetailsService - loadUserByUsername 메서드 호출
// 3-2. 실제 DB 에 username 이 존재하는지 확인하고
// 3-3. AuthenticationProvider 에서 비밀번호 일치 확인
// 3-4. 두조건 모두 확인되면 담은 새로운 PrincipalDetails 를 반환
// 3-5. 비밀번호는 provider 이 암호화된걸 풀어서 비교해줌 -> 일치하면 인증 완료, authentication 객체 반환

// 4. SecurityContext 에 authentication 정보(로그인한 정보)가 저장된다.(로그인요청사례) // JwtAuthenticationFilter 가 끝날때 마지막단계
// 4-1. SecurityContext 에 authentication 정보가 들어가있다? == 인증 잘 완료되서 저장됐다.

// 5. successfulAuthentication 실행됨 사용자에게 토큰 날려주고, 세션에 authentication 정보 저장함

// Tip: 인증 프로바이더의 디폴트 서비스는 UserDetailsService 타입
// Tip: 인증 프로바이더의 디폴트 암호화 방식은 BCryptPasswordEncoder
// 결론은 인증 프로바이더에게 알려줄 필요가 없음.

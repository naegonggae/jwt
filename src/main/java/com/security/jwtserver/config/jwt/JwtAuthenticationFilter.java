package com.security.jwtserver.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.jwtserver.config.auth.PrincipalDetails;
import com.security.jwtserver.model.User;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
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
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
	private final AuthenticationManager authenticationManager;

	// 로그인요청을 하면 로그인 시도를 위해서 실행되는 함수
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request,
			HttpServletResponse response) throws AuthenticationException {
		System.out.println("JwtAuthenticationFilter: 로그인 시도중");

		//1. username, password 받아서
		try {
//			// id, password 보여주기
//			BufferedReader br = request.getReader();
//
//			String input = null;
//			while ((input = br.readLine()) != null) {
//				System.out.println(input);
//			}

			ObjectMapper om = new ObjectMapper();
			User user = om.readValue(request.getInputStream(),
					User.class); // user 형태로 담고 밑에서 뽑아 토큰 만들기
			System.out.println("user = " + user);

			UsernamePasswordAuthenticationToken authenticationToken =
					new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

			// PrincipalDetailsService 에 loadUserByUsername 가 호출됨
			//authenticationManager 에 토큰을 넣어서 던지면 인증을 해줌 -> 인증을 하면 authentication 받음
			// authentication 뭐가 있냐? 내 로그인한 정보가 담김
			// DB에 있는 username 과 password 가 일치한다.
			Authentication authentication = authenticationManager.authenticate(authenticationToken);

			// 로그인이 정상적으로 되었다는 뜻
			PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
			System.out.println("로그인 완료됨 principalDetails = " + principalDetails.getUser().getUsername());
			System.out.println("1=====================");
			// authentication 객체가 session 영역에 저장을 해야하고 그 방법이 return 해주면 끝임
			// 리턴의 이유는 권한 관리를 시큐리티가 대신해주기때문에 편하려고 하는거임
			// 굳이 jwt 토큰을 사용하면서 세션을 만들이유가 없는데, 단지 권한 처리때문에 세션에 넣어줍니다.

			// 이제 jwt 토큰을 만드는데 여기에 만들필요가 없음 왜냐? -> attemptAuthentication 가 종료되고 그 뒤에 실행되는 함수가 있음
			// 그 함수는 바로 successfulAuthentication 임

			return authentication; // authentication 객체가 세션에 저장됨

			//System.out.println(request.getInputStream().toString()); // request.getInputStream() 안에 username 과 password 가 담김
		} catch (IOException e) {
			e.printStackTrace();
		}
		System.out.println("2====================");

		//2. 정상인지 로그인시도를 해보는거에요.
		//authenticationManager 로 로그인시도를 하면 PrincipalDetailsService 가 호출이 됨 ->  loadUserByUsername 호출

		//3. PrincipalDetails 를 세션에 담고 // 권한관리해주려고

		//4. jwt token 을 만들어서 응답해주면됨
		return null;
	}

	// attemptAuthentication 실행 후 정상적으로 인증이 되면 successfulAuthentication 함수가 실행이 되요
	// Jwt 토큰을 만들어서 request 요청한 사용자에게 jwt 토큰을 response 해주면됨
	@Override
	protected void successfulAuthentication(HttpServletRequest request,
			HttpServletResponse response, FilterChain chain, Authentication authResult)
			throws IOException, ServletException {
		System.out.println("successfulAuthentication 이 실행됨, 인증이 완료되었음");
		PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

		// jwt 토큰 만들기 - 빌더패턴
		// RSA 방식(공개키 개인키 방식)은 아니고 Hash 방식(secret 키를 갖는 방식)...
		String jwtToken = JWT.create()
				//.withSubject(principalDetails.getUsername())
				.withSubject("cos 토큰")
				//.withExpiresAt(new Date(System.currentTimeMillis()+JwtProperties.EXPIRATION_TIME)) // 만료시간
				.withExpiresAt(new Date(System.currentTimeMillis()+(60000*10))) // 60000 =1분
				.withClaim("id", principalDetails.getUser().getId())
				.withClaim("username", principalDetails.getUser().getUsername())
				//.sign(Algorithm.HMAC512(JwtProperties.SECRET)); // SECRET = 사이트만 알고있는 고유값
				.sign(Algorithm.HMAC512("cos"));
		System.out.println("jwtToken = " + jwtToken);


		response.addHeader("Authorization","Bearer " + jwtToken);
	}
}

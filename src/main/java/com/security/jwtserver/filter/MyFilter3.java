package com.security.jwtserver.filter;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class MyFilter3 implements Filter {

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		//다운캐스팅 진행
		HttpServletRequest req = (HttpServletRequest) request;
		HttpServletResponse res = (HttpServletResponse) response;

		// 토큰 : 코스로 날라올때만 필터로 진입가능하게
		// 근데 이필터는 시큐리티 필터가 동작하기 전에 돌아야함

		// id, pw 가 정확히 들어와서 로그인이 완료되면 토큰을 만들어주고 그걸 응답해준다.
		// 요청할때마다 header 에 Authorization 에 value 값으로 토큰을 가져오면 되겠죠?
		// 그때 토큰이 넘어오면 이 토큰이 내가 만든 토큰이 맞는지만 검증하면 됨 (RSA, HS256)
		if (req.getMethod().equals("POST")) {
			System.out.println("Post 요청됨");

			String headerAuth = req.getHeader("Authorization");
			System.out.println("headerAuth = " + headerAuth);
			System.out.println("필터3");

			if (headerAuth.equals("cos")) {
				chain.doFilter(req, res); // 계속진행하라고 체인에 넘겨줌
			} else {
				PrintWriter out = res.getWriter();
				out.println("인증안됨");
				System.out.println("인증안됨");
			}
		}
	}
}
